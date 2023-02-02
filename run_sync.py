import os
import sys
import json
import pickle
import hashlib

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


    azure = AdConnect()
    smb = SambaInfo()

    smb.generate_all_dict()

    #create all user found samba
    for entry in smb.dict_all_users_samba:
        data_hash = hash_for_data(smb.dict_all_users_samba[entry])
        if last_send_user.get(entry) != data_hash or force:
            azure.send_user_to_az(smb.dict_all_users_samba[entry])
            last_send_user[entry] = data_hash

    with open(file_last_send_user,'w') as f :
        f.write(json.dumps(last_send_user))



    #create all group found samba
    for entry in smb.dict_all_group_samba:
        data_hash = hash_for_data(smb.dict_all_group_samba[entry])
        if last_send_group.get(entry) != data_hash or force:
            azure.send_group_to_az(smb.dict_all_group_samba[entry])
            last_send_group[entry] = data_hash


    with open(file_last_send_group,'w') as f :
        f.write(json.dumps(last_send_group))



    azure.generate_all_dict()

    # Delete user in azure and not found in samba
    for user in azure.dict_az_user:
        if not user in smb.dict_all_users_samba:
            print('Delete user %s' % user)
            azure.delete_user(user)

    # Delete group in azure and not found in samba
    for group in azure.dict_az_group:
        if not group in smb.dict_all_group_samba:
            print('Delete group %s' % group)
            azure.delete_group(group)

    #send all_password
    for entry in smb.dict_id_hash :
        if last_send_password.get(entry) != smb.dict_id_hash[entry] or force:
            print('send %s to %s' % (smb.dict_id_hash[entry],entry))
            azure.send_hashnt(smb.dict_id_hash[entry],entry)
            last_send_password[entry] = smb.dict_id_hash[entry]

    with open(file_last_send_password,'w') as f :
        f.write(json.dumps(last_send_password))



    # TODO BACKUP LAST HASH

if __name__ == '__main__':
    run_sync(force=False)
