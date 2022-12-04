# Portal-To-MacAuthentication
Create a MAC Address AD User to Windows Active Directory starting from an AD User. This user will be used in NPS Server to execute MAC Authentication.

# Use Cases:
## TP-Link Omada
TP-Link Omada System has the limitation to not permit VLAN Assignment if portal login used. This script, combined with a Django Web Server, can resolve this issue: the Django web server can be set as external portal so the user will login with its AD Credential, the script will check if they are valid and then will create a MAC Address AD User to permit (instead of the User/Password Authentication) the MAC Based Authentication that supports VLAN Assignment.

# Usefull Links:
[How to setup NPS for Radius Authentication] (https://documentation.meraki.com/MS/Access_Control/Configuring_Microsoft_NPS_for_MAC-Based_RADIUS_-_MS_Switches)
[How to setup VLAN Assignment] https://www.expertnetworkconsultant.com/configuring/ieee-802-1x-authentication-and-dynamic-vlan-assignment-with-nps-radius-server/
