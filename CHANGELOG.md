# Changelog

## [2023-07-15]
- Improved logs, The output is now in json and out in /var/log/azure_ad_sync. customizable with "logfile" in config file. 
- Errors are now non-blocking but logged
- You can now run the script in service mode with "--service-mode" arg (for use with systemd). In this mode the synchronization interval is 600 seconds. You can change this value with "synchronization_interval_service" in the conf file.

## [2023-07-06]
- Multi-factor authentication support. 
  Use the old token to regenerate a new token. The tenant id is now required in conf file
  For the first run an external authentication and a copy paste will be necessary
- New available option in conf file : tenant_id, save_to_cache, use_cache , credential_cache_file

## [2023-06-18]
- add use_get_syncobjects in azure.conf by default = True (allows not to use the history of shipments given by microsoft but rather to rely on the local database to find the sourceanchoor. less reliable but useful if get_syncobjects fails. It would be so much easier if Microsoft gave the source anchor for groups and devices and not just users...)

## [2023-06-14]
- basedn option Add in azure.conf (for search in specific basedn in samba)
- alternate_login_id_attr option Add  in azure.conf (to set alternate attribute for login id (https://learn.microsoft.com/en-us/azure/active-directory/hybrid/connect/plan-connect-userprincipalname#alternate-login-id) for mapping on mail 

## [2023-05-13]
- Support for writing "CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration" in samba4
- Add azureadname config in azure.conf (use for write CN=Device Registration Configuration) 

## [2023-05-10]
- Add Device synchronization in sync (configuration in conf file)
- Force usertype in dict (restart a forced sync for users)
- Add onPremiseSecurityIdentifier and usercertificate for the user

## [2023-05-09]
- Add "do_delete" in the configuration file, if True, delete accounts with a "sourceanchor" online and not found in samba

## [2023-05-03]
- Switch from saving the last sendings of a json file to a sqlite database (restart of a forced synchronization)

## [2023-04-29]
- added backward compatibility of samba 4.13

## [2023-04-28]
- Added "hash_synchronization" option in the configuration file 

## [2023-04-27 - 2023-04-26]
switch to "microsoft azure ad connect" operating mode:
- Choice of sourceanchor in the configuration file
- objectGUID and ObjectSid are not decoded (byte) (convert to base64 when sending to azuread)
- possibility to use ms-ds-consistencyguid
- Added the possibility of a sourceanchor objectSID_str for backward compatibility with old version of the project.

## [2023-04-24]
- Added a pause when sending the password hash, otherwise too fast between account creation and password sending.
- Sending the group twice for nested groups, otherwise too fast between the creation of groups.

## [2023-04-21 - 2023-04-20]
- added "adsync" and "PasswordHashSync" enable (allows to run the script on an instance that has never seen "microsoft azure ad connect")

## [2023-02-02]
- Send only if data change, write last data send in json file
- Add attributes in the sync

## [2023-02-01]
- first working version, use obectsid decoded for sourceanchor
