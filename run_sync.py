import os
import sys
import json
import pickle
import hashlib
import time
import configparser

if "__file__" in locals():
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from libsync import AdConnect,SambaInfo
path_az=os.path.dirname(os.path.realpath(__file__))
last_send_user={}
file_last_send_user = os.path.join(path_az,'last_send_user.json')
last_send_group={}
file_last_send_group = os.path.join(path_az,'last_send_group.json')
last_send_password={}
file_last_send_password = os.path.join(path_az,'last_send_password.json')

path_az= os.path.dirname(os.path.realpath(__file__))

if os.path.isfile(file_last_send_user):
    with open(file_last_send_user,'r') as f:
        last_send_user=json.loads(f.read())

if os.path.isfile(file_last_send_group):
    with open(file_last_send_group,'r') as f:
        last_send_group=json.loads(f.read())

if os.path.isfile(file_last_send_password):
     with open(file_last_send_password,'r') as f:
        last_send_password=json.loads(f.read())

def hash_for_data(data):
    return hashlib.sha1(pickle.dumps(data)).hexdigest()

def run_sync(force=False):

    azureconf='/etc/azureconf/azure.conf'

    config = configparser.ConfigParser()
    config.read(azureconf)

    dry_run = config.getboolean('common', 'dry_run')

    if dry_run:
        print('DRY RUN ON: the script will not perform any actions')

    azure = AdConnect()
    azure.dry_run = dry_run
    azure.mailadmin = config.get('common', 'mailadmin')
    azure.passwordadmin = config.get('common', 'passwordadmin')
    azure.proxiesconf = config.get('common', 'proxy')

    smb = SambaInfo(SourceAnchorAttr=config.get('common', 'SourceAnchorAttr'))

    smb.write_msDSConsistencyGuid_if_empty = config.getboolean('common', 'write_msDSConsistencyGuid_if_empty')
    smb.use_msDSConsistencyGuid_if_exist = config.getboolean('common', 'use_msDSConsistencyGuid_if_exist')
    smb.dry_run = dry_run

    if not last_send_password :
        # enable ad sync
        print('enable ad sync')
        azure.enable_ad_sync()

        # enable password hash sync
        print('enable password hash sync')
        azure.enable_password_hash_sync()

    smb.generate_all_dict()
    azure.generate_all_dict()

    # Delete user in azure and not found in samba
    for user in azure.dict_az_user:
        if not user in smb.dict_all_users_samba:
            print('Delete user %s' % user)
            azure.delete_user(user)
            if user in last_send_user:
                del last_send_user[user]


    # Delete group in azure and not found in samba
    for group in azure.dict_az_group:
        if not group in smb.dict_all_group_samba:
            print('Delete group %s' % group)
            azure.delete_group(group)
            if group in last_send_group:
                del last_send_group[group]

    #create all user found samba
    for entry in smb.dict_all_users_samba:
        data_hash = hash_for_data(smb.dict_all_users_samba[entry])
        if last_send_user.get(entry) != data_hash or force:
            print('Send user %s' % entry)
            azure.send_user_to_az(smb.dict_all_users_samba[entry])
            last_send_user[entry] = data_hash

    if not dry_run :
        with open(file_last_send_user,'w') as f :
            f.write(json.dumps(last_send_user))

    #create all group found samba
    list_nested_group = {}
    list_group_create = {}

    for entry in smb.dict_all_group_samba:
        if not entry in last_send_group:
            list_group_create[entry] = None

    for entry in smb.dict_all_group_samba:
        data_hash = hash_for_data(smb.dict_all_group_samba[entry])
        if last_send_group.get(entry) != data_hash or force:
            print('Send group %s' % entry)
            azure.send_group_to_az(smb.dict_all_group_samba[entry])
            for g in smb.dict_all_group_samba[entry]["groupMembers"]:
                if g in list_group_create:
                    list_nested_group[entry] = None
            last_send_group[entry] = data_hash

    if list_nested_group:
        print('New group with nested detected wait 30s')
        time.sleep(30)
        for entry in list_nested_group:
            azure.send_group_to_az(smb.dict_all_group_samba[entry])

    if not dry_run :
        with open(file_last_send_group,'w') as f :
            f.write(json.dumps(last_send_group))



    #send all_password
    for entry in smb.dict_id_hash :
        if last_send_password.get(entry) != smb.dict_id_hash[entry] or force:
            print('send hash for %s' % (entry))

            # Microsoft is very slow between sending the account and sending the password
            try:
                azure.send_hashnt(smb.dict_id_hash[entry],entry)
            except Exception as e:
                if "Result" in str(e):
                    print('Fail, we may be a little too fast for microsoft, we will wait and try again ...' )
                    time.sleep(30)
                    azure.send_hashnt(smb.dict_id_hash[entry],entry)
                else:
                    raise

            last_send_password[entry] = smb.dict_id_hash[entry]

    if not dry_run :
        with open(file_last_send_password,'w') as f :
            f.write(json.dumps(last_send_password))



    # TODO BACKUP LAST HASH

if __name__ == '__main__':
    run_sync(force=False)
