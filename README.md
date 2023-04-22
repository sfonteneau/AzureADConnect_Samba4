Installation
========================

Test
=====
 - apt-get install python3-pip git
 - git clone https://github.com/sfonteneau/AzureADConnect_Samba4.git
 - mv AzureADConnect_Samba4 /opt/sync-azure
 - cd /opt/sync-azure/
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

Warning ! The sourceanchor is the sid! do not run on an existing installation!
userPrincipalName is used for the email address
