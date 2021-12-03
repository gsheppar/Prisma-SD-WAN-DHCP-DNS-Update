# Prisma SD-WAN LAN DNS (Preview)
The purpose of this script is to add or remove a DNS from all Branch DHCP Servers 

#### Features
 - ./update_dhcp_dns.py.py can be used to add or remove a DNS entry from LAN interfaces
 

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.6

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 - Add a DNS entry 
 1. ./update_dhcp_dns.py -A 8.8.8.8
 
 - Remove a DNS entry 
 1. ./update_dhcp_dns.py -R 8.8.8.8

 
### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
