import os
import sys

if "__file__" in locals():
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from libsync import AdConnect,SambaInfo


def run_sync():


    azure = AdConnect()
    smb = SambaInfo()

    smb.generate_all_dict()

    #create all user found samba
    for entry in smb.dict_all_users_samba:
        #TODO backup the last hash of the dict and send only in case of change
        azure.send_user_to_az(smb.dict_all_users_samba[entry])

    # TODO CREATE HASH FOR DATA USER AND BACKUP

    #create all group found samba
    for entry in smb.dict_all_group_samba:
        #TODO backup the last hash of the dict and send only in case of change
        azure.send_group_to_az(smb.dict_all_group_samba[entry])


    # TODO CREATE HASH FOR GROUP USER AND BACKUP

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
        #TODO backup the last hash of the dict and send only in case of change
        print('send %s to %s' % (smb.dict_id_hash[entry],entry))
        azure.send_hashnt(smb.dict_id_hash[entry],entry)


    # TODO BACKUP LAST HASH

if __name__ == '__main__':
    run_sync()

