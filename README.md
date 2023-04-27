Installation
========================

Test
=====
 - apt-get install python3-pip git
 - cd /tmp
 - git clone https://github.com/sfonteneau/AzureADConnect_Samba4.git
 - mv AzureADConnect_Samba4 /opt/sync-azure
 - cd /opt/sync-azure/
 - pip3 install -r requirements.txt
 - git submodule update --progress --init -- "AADInternals_python"
 - cd /opt/sync-azure/AADInternals_python
 - pip3 install -r requirements.txt
 - git submodule update --progress --init -- "python_wcfbin"
 - mkdir /etc/azureconf/
 - cd /opt/sync-azure
 - cp -f azure.conf.exemple /etc/azureconf/
 - Configure /etc/azureconf/azure.conf

You can try like this:

python3 /opt/sync-azure/run_sync.py

The script sends all users and groups a first time and then only sends what has been modified since the last send during the next launch.

Warning
========

The script does not support 2FA authentication for the "mailadmin" account indicated in the conf file

userPrincipalName is used for the email address

"password writeback" not supported

User and group management only (not device)


sourceanchor
***************

The default sourceanchor in azure.conf.exemple is the objectGUID with msDSConsistencyGuid! read : https://learn.microsoft.com/en-us/azure/active-directory/hybrid/plan-connect-design-concepts#using-ms-ds-consistencyguid-as-sourceanchor

You can run the script on a previous installation but you have to pay attention to the previous configuration of your azure ad connect (sourceanchor)

If "sourceanchor" changes, it will initiate object deletions and then object recreations. You must therefore choose your sourceanchor well and not change it

A dry_run mode allows you to run the script without making any changes


compatibility
================

The first version of this project used the "objectsid" string as "sourceanchor", this mode now corresponds to an "objectSID_str" as sourceanchor in the ini file, this mode does not exist with azure ad microsoft, so it should no longer be used.

