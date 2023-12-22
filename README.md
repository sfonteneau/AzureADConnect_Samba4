Notes
========================

If you use this script and it works correctly - please do not be lazy to put a star. This motivates me very much to develop my product. If you lack some functions, write about it. I will try to add them if they fit into the product concept.

Install notes
==============

```
apt-get install git
cd /tmp
git clone https://github.com/sfonteneau/AzureADConnect_Samba4.git
mv AzureADConnect_Samba4 /opt/sync-azure
cd /opt/sync-azure/
git submodule update --progress --init -- "AADInternals_python"
cd /opt/sync-azure/AADInternals_python
git submodule update --progress --init -- "python_wcfbin"
mkdir /etc/azureconf/
cd /opt/sync-azure
cp -f azure.conf.exemple /etc/azureconf/azure.conf
apt-get install python3-pycryptodome python3-peewee python3-passlib python3-xmltodict python3-requests python3-azure -y
```


If you are not under debian or if you do not have the packages available :

```
apt-get install python3-pip
pip3 install -r /opt/sync-azure/requirements.txt
pip3 install -r /opt/sync-azure/AADInternals_python/requirements.txt
```

 - Configure /etc/azureconf/azure.conf

You can try like this:

```
python3 /opt/sync-azure/run_sync.py
```

The script sends all users and groups a first time and then only sends what has been modified since the last send during the next launch.

Warning
========

* Please note that this project uses Microsoft APIs not officially documented. Microsoft may break compatibility at any time

* userPrincipalName is used for the email address (add alternate_login_id_attr=mail in azure.conf to use the mail attribute instead of the userPrincipalName attribute ) [1]

* "password writeback" not supported

* User and group management only (device optional)

[1] https://learn.microsoft.com/en-us/azure/active-directory/hybrid/connect/plan-connect-userprincipalname#alternate-login-id

sourceanchor
=============

The default sourceanchor in azure.conf.exemple is the objectGUID with msDSConsistencyGuid! read : https://learn.microsoft.com/en-us/azure/active-directory/hybrid/plan-connect-design-concepts#using-ms-ds-consistencyguid-as-sourceanchor

You can run the script on a previous installation but you have to pay attention to the previous configuration of your azure ad connect (sourceanchor)

> **Warning**
> If "sourceanchor" changes, it will initiate object deletions and then object recreations. You must therefore choose your sourceanchor well and not change it

A dry_run mode allows you to run the script without making any changes

advanced configuration
========================

using specific basedn
-----------------------------

You can specify a specific basedn for search in samba:

```
basedn = OU=TEST,DC=MYDOMAIN,DC=LAN
```

OR a base dn for each type of object:

```
basedn_user     = OU=USER,DC=MYDOMAIN,DC=LAN
basedn_group    = OU=GROUP,DC=MYDOMAIN,DC=LAN
basedn_computer = OU=COMPUTER,DC=MYDOMAIN,DC=LAN
```

For precisely several bases dn, separate them with | 

```
basedn_user     = OU=USER,DC=MYDOMAIN,DC=LAN|OU=USER2,DC=MYDOMAIN,DC=LAN
```

custom filter for search
-----------------------------

You can specify a specific custom ldap filter for search in samba:

```
custom_filter_user     = (memberof:1.2.840.113556.1.4.1941:=CN=group_users,OU=Groupe,DC=mydomain,DC=lan)
custom_filter_group    = (memberof:1.2.840.113556.1.4.1941:=CN=group_groups,OU=Groupe,DC=mydomain,DC=lan)
custom_filter_computer = (memberof:1.2.840.113556.1.4.1941:=CN=group_computers,OU=Groupe,DC=mydomain,DC=lan)
```

Do not use userPrincipalName as login
----------------------------------------

You can specify which attribute should be used as login. Please note this must be an email address. Use alternate_login_id_attr


```
alternate_login_id_attr = mail
```

other settings
----------------------------------------

* credential_cache_file :


specifies where the last connection token will be stored and read:

```
credential_cache_file = /root/last_token.json
```

* dbpath :


specifies where the db that stores the state of the last scan will be stored:

```
dbpath = /root/last_send_azuread.db
```

* calculate_deletions_based_on_last_sync :

calculate deletions based on local last sync, does not list the users, groups and devices of the Azure AD to calculate the necessary deletion and will make the comparison with the last send of the script. Much faster mode 

```
calculate_deletions_based_on_last_sync=True
```

Samba configuration
---------------------------------------------

You can add pathsmbconf and pathsamdb parameters in the configuration file. 
If you are using a samba version of the distribution this should not be necessary.

```
pathsamdb   = /usr/local/samba/private/sam.ldb
pathsmbconf = /usr/local/samba/lib/smb.conf
```

Use Python callback to modify the calculated result of the script
-----------------------------------------------------------------------------

Copy callback_template:

```
cp -r /opt/sync-azure/callback_template /root/callbackaad
```

add option in config file : 

```
folder_callback_python = /root/callbackaad
```

Now edit /root/callbackaad/callbackaadsync.py

Exemple: 

```
def callback_user(sambaobj=None,entry=None,result=None):
    result['company'] = "MY ENTERPRISE"
    return result
```

In this example we force the company entry "MY ENTERPRISE" on all user entries

- sambaobj is the already instantiated samdb object, it can be used to do searches

- Entry is user entry returned by samdb

- result is resultcalculated by the script so you can modify it

The function returns the result modify, if the function returns None, the user will be skipped from the sync


compatibility
================

The first version of this project used the "objectsid" string as "sourceanchor", this mode now corresponds to an "objectSID_str" as sourceanchor in the ini file, this mode does not exist with azure ad microsoft, so it should no longer be used.

