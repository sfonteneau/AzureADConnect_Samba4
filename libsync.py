#!/usr/bin/env python
import os
import sys
import json
import ldb
import base64

from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.netcmd.user import GetPasswordCommand
from AADInternals_python.AADInternals import AADInternals
from Crypto import Random
from samba.dsdb import UF_ACCOUNTDISABLE

import optparse
import samba.getopt as options


class AdConnect():

    def __init__(self):


        self.mailadmin = None
        self.passwordadmin = None
        self.proxiesconf = None

        self.dry_run=True

        self.az = None
        self.dict_az_user={}
        self.dict_az_group={}

    def connect(self):
        if not self.az:
            self.az = AADInternals(mail=self.mailadmin,password=self.passwordadmin,proxies=self.proxiesconf)
            self.mailadmin = None
            self.passwordadmin = None

    def enable_ad_sync(self):
        self.connect()
        if not self.dry_run:
            self.az.set_adsyncenabled(enabledirsync=True)

    def enable_password_hash_sync(self):
        self.connect()
        if not self.dry_run:
            self.az.set_sync_features(enable_features=['PasswordHashSync'])

    def send_obj_to_az(self,entry):
        self.connect()
        if not self.dry_run:
            self.az.set_azureadobject(**entry)

    def delete_user(self,entry):
        if not self.dry_run:
            self.az.remove_azureadoject(sourceanchor=entry,objecttype='User')

    def delete_group(self,entry):
        if not self.dry_run:
            self.az.remove_azureadoject(sourceanchor=entry,objecttype='Group')

    def generate_all_dict(self):
        self.connect()
        self.dict_az_user = {}
        for user in self.az.list_users():
            if not user['dirSyncEnabled']:
                continue
            if not user.get('immutable_id'):
                continue
            self.dict_az_user[user["immutable_id"]] = user

        self.dict_az_group = {}
        for group in self.az.list_groups():
            if not group['dirSyncEnabled']:
                continue
            if not group.get('immutable_id'):
                continue
            self.dict_az_group[group["immutable_id"]] = group

    def send_hashnt(self,hashnt,sourceanchor):
        self.connect()
        if not self.dry_run:
            self.az.set_userpassword(hashnt=hashnt,sourceanchor=sourceanchor)


class SambaInfo():

    def __init__(self, smbconf="/etc/samba/smb.conf",SourceAnchorAttr="objectSid"):

        parser = optparse.OptionParser(smbconf)
        sambaopts = options.SambaOptions(parser)

        # SAMDB
        lp = sambaopts.get_loadparm()
        self.domaine = sambaopts._lp.get('realm').lower()

        creds = Credentials()
        creds.guess(lp)

        self.samdb_loc = SamDB(session_info=system_session(),credentials=creds, lp=lp)
        self.testpawd = GetPasswordCommand()
        self.testpawd.lp = lp

        self.dict_all_users_samba={}
        self.dict_all_device_samba={}
        self.all_dn={}
        self.dict_id_hash = {}
        self.SourceAnchorAttr = SourceAnchorAttr

        self.dry_run=True
        self.write_msDSConsistencyGuid_if_empty = None
        self.use_msDSConsistencyGuid_if_exist = None
        self.add_device= False


    def return_source_anchor(self,entry):

        sid = self.samdb_loc.schema_format_value("objectSID", entry["objectSID"][0]).decode('utf-8')

        if sid.startswith('S-1-5-32-'):
            return ""
        if int(sid.rsplit('-',)[-1]) < 1000:
            return ""

        if self.SourceAnchorAttr.lower() == "objectSID_str".lower():
            SourceAnchor = sid
        else:
            SourceAnchor = entry[self.SourceAnchorAttr][0]

        if type(SourceAnchor) == str:
            SourceAnchor = SourceAnchor.encode('utf-8')

        msDSConsistencyGuid = entry.get("ms-DS-ConsistencyGuid",[b''])[0]

        if self.use_msDSConsistencyGuid_if_exist:
            if msDSConsistencyGuid :
                SourceAnchor = msDSConsistencyGuid

        try:
            decode_SourceAnchor = SourceAnchor.decode('utf-8')
        except:
            decode_SourceAnchor= base64.b64encode(SourceAnchor).decode('utf-8')

        if self.write_msDSConsistencyGuid_if_empty:
            if not msDSConsistencyGuid :
                ldif_data = """dn: %s
changetype: modify
replace: ms-DS-ConsistencyGuid
ms-DS-ConsistencyGuid:: %s
""" % (entry['distinguishedName'][0].decode('utf-8'), base64.b64encode(SourceAnchor).decode('utf-8'))
                print('Set ms-DS-ConsistencyGuid=%s on %s ' % (decode_SourceAnchor,entry['distinguishedName'][0].decode('utf-8')))
                if not self.dry_run:
                    self.samdb_loc.modify_ldif(ldif_data)

        return decode_SourceAnchor



    def generate_all_dict(self):
        self.dict_all_users_samba={}
        self.all_dn={}
        self.dict_id_hash = {}
        # Search all users
        for user in self.samdb_loc.search(base=self.samdb_loc.get_default_basedn(), expression=r"(&(objectClass=user)(!(objectClass=computer)))"):

            Random.atfork()

            # Update if password different in dict mail pwdlastset
            passwordattr = 'unicodePwd'
            password = self.testpawd.get_account_attributes(self.samdb_loc,None,self.samdb_loc.get_default_basedn(),filter="(sAMAccountName=%s)" % str(user["sAMAccountName"]) ,scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr],decrypt=False)
            if not passwordattr in password:
                continue

            hashnt = password[passwordattr][0].hex().upper()

            SourceAnchor = self.return_source_anchor(user)
            if not SourceAnchor:
                continue


            self.dict_id_hash[SourceAnchor]=hashnt
            if int(user["userAccountControl"][0]) & UF_ACCOUNTDISABLE:
                enabled = False
            else:
                enabled = True
            data = {
                       "SourceAnchor"               : SourceAnchor,
                       "accountEnabled"             : enabled,
                       "userPrincipalName"          : user.get("userPrincipalName",[b''])[0].decode('utf-8'),
                       "onPremisesSamAccountName"   : user.get("sAMAccountName",[b''])[0].decode('utf-8'),
                       "onPremisesDistinguishedName": str(user["dn"]),
                       "dnsDomainName"              : self.domaine,
                       "displayName"                : user.get("displayName",[b''])[0].decode('utf-8'),
                       "onPremiseSecurityIdentifier": base64.b64encode(user["objectSid"][0]).decode('utf-8'),
                       "userCertificate"            : [base64.b64encode(c).decode('utf-8') for c in user.get("userCertificate",[])],
                       "givenName"                  : user.get("givenName",[b''])[0].decode('utf-8'),
                       "surname"                    : user.get("sn",[b''])[0].decode('utf-8'),
                       "commonName"                 : user.get("cn",[b''])[0].decode('utf-8'),
                       "physicalDeliveryOfficeName" : user.get("physicalDeliveryOfficeName",[b''])[0].decode('utf-8'),
                       "department"                 : user.get("department",[b''])[0].decode('utf-8'),
                       "employeeId"                 : user.get("employeeId",[b''])[0].decode('utf-8'),
                       "streetAddress"              : user.get("streetAddress",[b''])[0].decode('utf-8'),
                       "city"                       : user.get("city",[b''])[0].decode('utf-8'),
                       "state"                      : user.get("state",[b''])[0].decode('utf-8'),
                       "telephoneNumber"            : user.get("telephoneNumber",[b''])[0].decode('utf-8'),
                       "company"                    : user.get("company",[b''])[0].decode('utf-8'),
                       "employeeType"               : user.get("employeeType",[b''])[0].decode('utf-8'),
                       "facsimileTelephoneNumber"   : user.get("facsimileTelephoneNumber",[b''])[0].decode('utf-8'),
                       "mail"                       : user.get("mail",[b''])[0].decode('utf-8'),
                       "mobile"                     : user.get("mobile",[b''])[0].decode('utf-8'),
                       "title"                      : user.get("title",[b''])[0].decode('utf-8'),
                       "proxyAddresses"             : [p.decode('utf-8') for p in user.get("proxyAddresses",[])],
                       "usertype"                   : "User"
                   }
            self.all_dn[str(user["dn"])]=SourceAnchor
            self.dict_all_users_samba[SourceAnchor] = data


        if self.add_device:
            self.dict_all_device_samba={}

            for device in self.samdb_loc.search(base=self.samdb_loc.get_default_basedn(), expression=r"(objectClass=computer)"):

                SourceAnchor = self.return_source_anchor(device)
                if not SourceAnchor:
                    continue

                data = {
                            "SourceAnchor"               : SourceAnchor,
                            "onPremisesSamAccountName"   : device.get("sAMAccountName",[b''])[0].decode('utf-8'),
                            "onPremisesDistinguishedName": str(device["dn"]),
                            "dnsDomainName"              : self.domaine,
                            "displayName"                : device.get("sAMAccountName",[b''])[0].decode('utf-8').strip('$'),
                            "onPremiseSecurityIdentifier": base64.b64encode(device["objectSid"][0]).decode('utf-8'),
                            "userCertificate"            : [base64.b64encode(c).decode('utf-8') for c in device.get("userCertificate",[])],
                            "deviceTrustType"            : "ServerAd",
                            "deviceId"                   : base64.b64encode(device["objectGUID"][0]).decode('utf-8'),
                            "deviceOSType"               : "windows",
                            "usertype"                   : "Device"
                        }

                self.all_dn[str(device["dn"])]=SourceAnchor
                self.dict_all_device_samba[SourceAnchor] = data            


        self.dict_all_group_samba = {}
        for group in self.samdb_loc.search(base=self.samdb_loc.get_default_basedn(), expression=r"(objectClass=group)"):

            SourceAnchor = self.return_source_anchor(group)
            if not SourceAnchor:
                continue

            data = {
                           "SourceAnchor"               : SourceAnchor,
                           "onPremisesSamAccountName"   : group.get("sAMAccountName",[b''])[0].decode('utf-8'),
                           "onPremisesDistinguishedName": str(group["dn"]),
                           "dnsDomainName"              : self.domaine,
                           "displayName"                : group.get("sAMAccountName",[b''])[0].decode('utf-8'),
                           "groupMembers"               : [],
                           "SecurityEnabled"            : group.get("grouptype",[b''])[0].decode('utf-8') in ['-2147483644','-2147483640','-2147483646'],
                           "usertype"                   : "Group"
                       }

            self.all_dn[str(group["dn"])]=SourceAnchor
            self.dict_all_group_samba[SourceAnchor] = data


        for group in self.samdb_loc.search(base=self.samdb_loc.get_default_basedn(), expression=r"(objectClass=group)"):

            SourceAnchor = self.return_source_anchor(group)
            if not SourceAnchor:
                continue

            list_member=[]
            for m in group.get('member',[]):
                if str(m) in self.all_dn:
                    list_member.append(self.all_dn[str(m)])
            self.dict_all_group_samba[SourceAnchor]['groupMembers']=list_member
