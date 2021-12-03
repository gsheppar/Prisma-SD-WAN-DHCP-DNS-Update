#!/usr/bin/env python3

# 20201020 - Add a function to add a single prefix to a local prefixlist - Dan
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed
import cloudgenix_settings
import sys
import logging
import os
import datetime
import collections
import csv
from csv import DictReader
import time
import collections
import ipaddress
from datetime import datetime, timedelta
jdout = cloudgenix.jdout


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: Update DHCP DNS'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)


####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None

def dhcp_add(cgx, dns_entry):
    
    try:
        ipaddress.ip_address(dns_entry)
    except:
        print("Please provide a valid IP address")
        return
    
    # Build a list of sites 
    site_list = []
    site_id2n = {}
    for site in cgx.get.sites().cgx_content["items"]:
        if site['element_cluster_role'] == 'SPOKE':
                site_list.append(site['id'])
                site_id2n[site['id']] = site['name']
    
    for site in site_list:
        try:
            for dhcp in cgx.get.dhcpservers(site_id=site).cgx_content["items"]:
                dhcp_check = True
                dns_list = dhcp["dns_servers"]
            
                if dns_entry in dns_list:
                    print("DHCP server " + dns_entry + " on site " + site_id2n[site] + " already exsists")
                else:
                    dns_list.append(dns_entry)
                    dhcp["dns_servers"] = dns_list           
                    resp = cgx.put.dhcpservers(site_id=site, dhcpserver_id=dhcp['id'], data=dhcp)
                    if not resp:
                        print("Error adding DHCP server " + dns_entry + " on " + site_id2n[site])
                        print(str(jdout(resp)))
                    else:
                        print("Adding DHCP server " + dns_entry + " on site " + site_id2n[site])
        except:
            print("Failed checking DHCP servers on " + site_id2n[site])
    
    print("\nCompleted DNS changes on all sites")

def dhcp_remove(cgx, dns_entry):
    
    try:
        ipaddress.ip_address(dns_entry)
    except:
        print("Please provide a valid IP address")
        return
    
    # Build a list of sites 
    site_list = []
    site_id2n = {}
    for site in cgx.get.sites().cgx_content["items"]:
        if site['element_cluster_role'] == 'SPOKE':
                site_list.append(site['id'])
                site_id2n[site['id']] = site['name']
    
    for site in site_list:
        try:
            for dhcp in cgx.get.dhcpservers(site_id=site).cgx_content["items"]:
                dhcp_check = True
                dns_list = dhcp["dns_servers"]
            
                if dns_entry not in dns_list:
                    print("DHCP server " + dns_entry + " on site " + site_id2n[site] + " is already gone")
                else:
                    dns_list.remove(dns_entry)
                    if dns_list:
                        dhcp["dns_servers"] = dns_list
                    else:
                        dhcp["dns_servers"] = None

                    resp = cgx.put.dhcpservers(site_id=site, dhcpserver_id=dhcp['id'], data=dhcp)
                    if not resp:
                        print("Error removing DHCP server " + dns_entry + " on " + site_id2n[site])
                        print(str(jdout(resp)))
                    else:
                        print("Removing DHCP server " + dns_entry + " on site " + site_id2n[site])
        except:
            print("Failed checking DHCP servers on " + site_id2n[site])
        
    
    print("\nCompleted DNS changes on all sites")

                                          
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    
    config_group = parser.add_argument_group('Config', 'These options change how the configuration is generated.')
    config_group.add_argument('--add', '-A', help='Add DNS entry')
    config_group.add_argument('--remove', '-R', help='Remove DNS entry')
    
    
    args = vars(parser.parse_args())
                             
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    
    if args["add"]:
        dhcp_add(cgx, args['add'])
    elif args["remove"]:
        dhcp_remove(cgx, args['remove'])
    else:
        print("Please add an arugment to either add (-A) or remove (-R) a DNS server ")
    
    
    # end of script, run logout to clear session.
    cgx_session.get.logout()

if __name__ == "__main__":
    go()