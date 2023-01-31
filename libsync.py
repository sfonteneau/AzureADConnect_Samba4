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

    # Search all users

    for user in samdb_loc.search(base=samdb_loc.get_default_basedn(), expression=r"(&(objectClass=user)(!(objectClass=computer)))"):

            Random.atfork()

            passwordattr = 'unicodePwd'
            password = testpawd.get_account_attributes(samdb_loc,None,samdb_loc.get_default_basedn(),filter="(sAMAccountName=%s)" % str(user["sAMAccountName"]) ,scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr],decrypt=False)
            if not passwordattr in password:
                continue

            hashnt = password[passwordattr][0].hex().upper()

            sid = sid_to_str(user['objectSid'][0])

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

            dict_all_users_samba[sid] = data

    az = AADInternals(mail=mailadmin,password=passwordadmin)
    for entry in dict_all_users_samba:
        az.set_azureadobject(entry,
                             dict_all_users_samba[entry]['userPrincipalName'],
                             givenName=dict_all_users_samba[entry]['givenName'],
                             dnsDomainName=dict_all_users_samba[entry]["dnsDomainName"],
                             displayName=dict_all_users_samba[entry]["displayName"],
                             surname=dict_all_users_samba[entry]['surname']
        )
