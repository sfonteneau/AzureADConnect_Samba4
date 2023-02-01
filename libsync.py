 #!/usr/bin/env python
import os
import sys
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

parser = optparse.OptionParser("/etc/samba/smb.conf")
sambaopts = options.SambaOptions(parser)

config = configparser.ConfigParser()
config.read('/etc/azureconf/azure.conf')


## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

mailadmin = config.get('common', 'mailadmin')
passwordadmin = config.get('common', 'passwordadmin')

proxiesconf = config.get('common', 'proxy')
if proxiesconf:
    proxies={'http':proxiesconf,'https':proxiesconf}
else:
    proxies={}

az = None


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

def connect_az():
    global az
    if not az :
        az = AADInternals(mail=mailadmin,password=passwordadmin)



def send_user_to_az(entry):
    global az

    connect_az()
    print('Create User %s' % entry)
    az.set_azureadobject(entry['SourceAnchor'],
                         entry['userPrincipalName'],
                         givenName=entry['givenName'],
                         dnsDomainName=entry["dnsDomainName"],
                         displayName=entry["displayName"],
                         surname=entry['surname']
    )

def send_group_to_az(entry):
    global az

    connect_az()
    print('Create Group %s' % entry)
    az.set_azureadobject(entry['SourceAnchor'],
                         dnsDomainName=entry["dnsDomainName"],
                         displayName=entry["displayName"],
                         groupMembers=entry['groupMembers'],
                         usertype='Group',
                         SecurityEnabled=True
    )




def run():



    # SAMDB
    lp = sambaopts.get_loadparm()
    domaine = sambaopts._lp.get('realm').lower()

    creds = Credentials()
    creds.guess(lp)

    samdb_loc = SamDB(session_info=system_session(),credentials=creds, lp=lp)
    testpawd = GetPasswordCommand()
    testpawd.lp = lp

    dict_all_users_samba={}

    all_dn={}
    dict_id_hash = {}
    # Search all users
    for user in samdb_loc.search(base=samdb_loc.get_default_basedn(), expression=r"(&(objectClass=user)(!(objectClass=computer)))"):

            Random.atfork()

            # Update if password different in dict mail pwdlastset
            passwordattr = 'unicodePwd'
            password = testpawd.get_account_attributes(samdb_loc,None,samdb_loc.get_default_basedn(),filter="(sAMAccountName=%s)" % str(user["sAMAccountName"]) ,scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr],decrypt=False)
            if not passwordattr in password:
                continue

            hashnt = password[passwordattr][0].hex().upper()

            sid = sid_to_str(user['objectSid'][0])
            if sid.startswith('S-1-5-32-'):
                continue
            dict_id_hash[sid]=hashnt
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
                       "dnsDomainName"              : domaine,
                       "displayName"                : user.get("displayName",[b''])[0].decode('utf-8'),
                       "givenName"                  : user.get("givenName",[b''])[0].decode('utf-8'),
                       "surname"                    : user.get("sn",[b''])[0].decode('utf-8'),
                   }
            all_dn[str(user["dn"])]=sid
            dict_all_users_samba[sid] = data


    dict_all_group_samba = {}
    for group in samdb_loc.search(base=samdb_loc.get_default_basedn(), expression=r"(objectClass=group)"):
        sid = sid_to_str(group['objectSid'][0])
        if sid.startswith('S-1-5-32-'):
            continue

        data = {
                       "SourceAnchor"               : sid,
                       "onPremisesSamAccountName"   : group.get("sAMAccountName",[b''])[0].decode('utf-8'),
                       "onPremisesDistinguishedName": str(group["dn"]),
                       "dnsDomainName"              : domaine,
                       "displayName"                : group.get("sAMAccountName",[b''])[0].decode('utf-8'),
                       "groupMembers"               : []
                   }

        all_dn[str(group["dn"])]=sid
        dict_all_group_samba[sid] = data


    for group in samdb_loc.search(base=samdb_loc.get_default_basedn(), expression=r"(objectClass=group)"):
        sid = sid_to_str(group['objectSid'][0])
        if sid.startswith('S-1-5-32-'):
            continue

        list_member=[]
        for m in group.get('member',[]):
            if str(m) in all_dn:
                list_member.append(all_dn[str(m)])
        dict_all_group_samba[sid]['groupMembers']=list_member



    for entry in dict_all_users_samba:
        send_user_to_az(dict_all_users_samba[entry])

    for entry in dict_all_group_samba:
        send_group_to_az(dict_all_group_samba[entry])

    #create dict azure as User
    global az
    dict_az_user = {}
    connect_az()
    for user in az.list_users():
        if not user['dirSyncEnabled']:
            continue
        if not user.get('immutable_id'):
            continue
        dict_az_user[user["immutable_id"]] = user


    # Delete user in azure ad not found in samba
    for user in dict_az_user:
        if not user in dict_all_users_samba:
            print('Delete user %s' % user)
            az.remove_azureadoject(sourceanchor=user,objecttype='User')

    dict_az_group = {}
    for group in az.list_groups():
        if not group['dirSyncEnabled']:
            continue
        if not group.get('immutable_id'):
            continue
        dict_az_group[group["immutable_id"]] = group

    # Delete group in azure ad not found in samba
    for group in dict_az_group:
        if not group in dict_all_group_samba:
            print('Delete group %s' % group)
            az.remove_azureadoject(sourceanchor=group,objecttype='Group')


    for entry in dict_id_hash :
        print('send %s to %s' % (hashnt,entry))
        az.set_userpassword(hashnt=dict_id_hash[entry],sourceanchor=entry)
