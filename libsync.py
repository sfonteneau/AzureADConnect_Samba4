 #!/usr/bin/env python
import os
import sys

if "__file__" in locals():
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)),'AADInternals_python'))

import syslog
import json
import ldb

from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.netcmd.user import GetPasswordCommand
from AADInternals_python.AADInternals import AADInternals
from Crypto import Random
from samba.dsdb import UF_ACCOUNTDISABLE

import configparser
import optparse
import samba.getopt as options


## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)



def sid_to_str(sid):

    try:
        # revision
        revision = int(sid[0])
        # count of sub authorities
        sub_authorities = int(sid[1])
        # big endian
        identifier_authority = int.from_bytes(sid[2:8], byteorder='big')
        # If true then it is represented in hex
        if identifier_authority >= 2 ** 32:
            identifier_authority = hex(identifier_authority)

        # loop over the count of small endians
        sub_authority = '-' + '-'.join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder='little')) for i in range(sub_authorities)])
        objectSid = 'S-' + str(revision) + '-' + str(identifier_authority) + sub_authority

        return objectSid
    except Exception:
        pass

    return sid

class AdConnect():

    def __init__(self,azureconf='/etc/azureconf/azure.conf'):

        config = configparser.ConfigParser()
        config.read(azureconf)
        self.mailadmin = config.get('common', 'mailadmin')
        self.passwordadmin = config.get('common', 'passwordadmin')
        self.proxiesconf = config.get('common', 'proxy')


        self.az = None
        self.dict_az_user={}
        self.dict_az_group={}

    def connect(self):
        if not self.az:
            self.az = AADInternals(mail=self.mailadmin,password=self.passwordadmin,proxies=self.proxiesconf)
            self.mailadmin = None
            self.passwordadmin = None

    def send_user_to_az(self,entry):
        self.connect()
        print('Create User %s' % entry)
        self.az.set_azureadobject(entry['SourceAnchor'],
                             entry['userPrincipalName'],
                             givenName=entry['givenName'],
                             dnsDomainName=entry["dnsDomainName"],
                             displayName=entry["displayName"],
                             surname=entry['surname']
        )

    def send_group_to_az(self,entry):
        self.connect()
        print('Create Group %s' % entry)
        self.az.set_azureadobject(entry['SourceAnchor'],
                             dnsDomainName=entry["dnsDomainName"],
                             displayName=entry["displayName"],
                             groupMembers=entry['groupMembers'],
                             usertype='Group',
                             SecurityEnabled=True
        )

    def delete_user(self,entry):
        self.az.remove_azureadoject(sourceanchor=entry,objecttype='User')

    def delete_group(self,entry):
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
        self.az.set_userpassword(hashnt=hashnt,sourceanchor=sourceanchor)


class SambaInfo():

    def __init__(self, smbconf="/etc/samba/smb.conf"):

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
        self.all_dn={}
        self.dict_id_hash = {}


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

            sid = sid_to_str(user['objectSid'][0])
            if sid.startswith('S-1-5-32-'):
                continue
            self.dict_id_hash[sid]=hashnt
            if int(user["userAccountControl"][0]) & UF_ACCOUNTDISABLE:
                enabled = False
            else:
                enabled = True
            data = {
                       "SourceAnchor"               : sid,
                       "accountEnabled"             : enabled,
                       "userPrincipalName"          : user.get("userPrincipalName",[b''])[0].decode('utf-8'),
                       "onPremisesSamAccountName"   : user.get("sAMAccountName",[b''])[0].decode('utf-8'),
                       "onPremisesDistinguishedName": str(user["dn"]),
                       "dnsDomainName"              : self.domaine,
                       "displayName"                : user.get("displayName",[b''])[0].decode('utf-8'),
                       "givenName"                  : user.get("givenName",[b''])[0].decode('utf-8'),
                       "surname"                    : user.get("sn",[b''])[0].decode('utf-8'),
                   }
            self.all_dn[str(user["dn"])]=sid
            self.dict_all_users_samba[sid] = data


        self.dict_all_group_samba = {}
        for group in self.samdb_loc.search(base=self.samdb_loc.get_default_basedn(), expression=r"(objectClass=group)"):
            sid = sid_to_str(group['objectSid'][0])
            if sid.startswith('S-1-5-32-'):
                continue

            data = {
                           "SourceAnchor"               : sid,
                           "onPremisesSamAccountName"   : group.get("sAMAccountName",[b''])[0].decode('utf-8'),
                           "onPremisesDistinguishedName": str(group["dn"]),
                           "dnsDomainName"              : self.domaine,
                           "displayName"                : group.get("sAMAccountName",[b''])[0].decode('utf-8'),
                           "groupMembers"               : []
                       }

            self.all_dn[str(group["dn"])]=sid
            self.dict_all_group_samba[sid] = data


        for group in self.samdb_loc.search(base=self.samdb_loc.get_default_basedn(), expression=r"(objectClass=group)"):
            sid = sid_to_str(group['objectSid'][0])
            if sid.startswith('S-1-5-32-'):
                continue

            list_member=[]
            for m in group.get('member',[]):
                if str(m) in self.all_dn:
                    list_member.append(self.all_dn[str(m)])
            self.dict_all_group_samba[sid]['groupMembers']=list_member
