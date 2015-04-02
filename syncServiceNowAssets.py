#!/usr/bin/env python

# Copyright (c) 2014, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Brian Torres-Gil <btorres-gil@paloaltonetworks.com>


"""
This script is used to synchronize ServiceNow assets with a
Palo Alto Networks firewall.

The following steps are performed:
 1. Get a list of the assets in a ServiceNow portal
 2. Checks for any assets in the 'Server' section that have both
    a hostname and ip address set
 3. Creates Address Objects on a Palo Alto Networks firewall or
    Panorama that match those hostname/ip combinations
"""


# import modules
import sys
import os
import argparse
import logging
import urllib2
import json
import re

from pandevice import device
from pan.xapi import PanXapiError


def retrieve_servicenow_asset_list(sn_username, sn_password, sn_fqdn):
    logging.info("Retrieving assets from ServiceNow")
    #TODO: sanitize fqdn format
    url = "https://%s/cmdb_ci_server_list.do?JSON&sysparm_action=getRecords" % sn_fqdn

    password_manager = urllib2.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, sn_username, sn_password)

    auth = urllib2.HTTPBasicAuthHandler(password_manager)  # create an authentication handler
    opener = urllib2.build_opener(auth)  # create an opener with the authentication handler
    urllib2.install_opener(opener)  # install the opener...

    request = urllib2.Request(url)
    try:
        handler = urllib2.urlopen(request)
    except urllib2.HTTPError as e:
        logging.error('can\'t read assets from ServiceNow: urllib2: %s' % e.code)
        sys.exit(1)

    return handler.read()  # return JSON text


def parse_servicenow_assets(json_assets):
    #TODO: verify it is JSON formatted or handle error on loads() function
    assets = json.loads(json_assets)
    assets = assets['records']
    logging.info("%d assets parsed from ServiceNow" % len(assets))

    interesting_assets = []

    for asset in assets:
        hostname = asset['host_name']
        ip_address = asset['ip_address']
        name = asset['name']
        operating_system = asset['os']
        classification = asset['classification']
        # only add assets with a hostname and ip address
        if hostname != '' and ip_address != '':
            # set the class (eg. server, win, linux, aix, etc.)
            match_class = re.match(r"cmdb_ci_(\w*)_server", asset['sys_class_name'])
            if match_class:
                asset_class = match_class.group(1)
                asset_class = asset_class.replace('win', 'windows')
            else:
                asset_class = None
            interesting_assets.append({'host_name': hostname,     # Hostname
                                       'ip_address': ip_address,  # IP Address
                                       'name': name,              # Asset Name
                                       'class': asset_class,      # windows, linux, aix, unix
                                       'os': operating_system,    # Operating System
                                       'superclass': 'server',    # Always 'server'
                                       'classification': classification,
                                       })
    return interesting_assets


def sync_address_objects(device, objects, no_delete=False):
    logging.info("Begin sync with firewall/panorama address objects")
    # remove any objects that aren't in ServiceNow
    try:
        if not no_delete:
            logging.info("Delete is allowed. Getting current address objects "
                          "from firewall/panorama for comparison")

            current_address_objects = device.get_all_address_objects()

            if current_address_objects and 'entry' in current_address_objects['address']:
                current_address_objects = current_address_objects['address']['entry']

                for fw_address in current_address_objects:
                    # look for firewall objects of the form used
                    # by ServiceNow sync
                    match = re.match(
                        r"^SN_(.*)_((?:[0-9]{1,3}\.){3}[0-9]{1,3})$",
                        fw_address['name']
                    )
                    if match:
                        hostname = match.group(1)
                        ip = match.group(2)
                        # if the firewall's address object is not in the
                        # ServiceNow asset list, then remove the object from
                        # the firewall
                        object_in_servicenow = next((sn_object for sn_object in objects if (sn_object['host_name'] == hostname and sn_object['ip_address'] == ip)), None)
                        if not object_in_servicenow:
                            logging.info("Removing address object on firewall/panorama: %s", fw_address['name'])
                            device.delete_address_object(fw_address['name'])

        # add/update objects on firewall/panorama
        for address in objects:
            name = "SN_%s_%s" % (address['host_name'], address['ip_address'])
            description = "Synced from ServiceNow asset: %s" % address['name']
            #TODO: verify format of ip_address
            ip_address = address['ip_address']
            logging.info("Adding/updating address object in firewall/panorama: %s" % name)
            device.add_address_object(name, ip_address, description)

    except PanXapiError as msg:
        logging.error('pan.xapi.PanXapi:%s' % msg)
        sys.exit(1)


def sync_dynamic_address_objects(device, objects, no_delete=False):
    # servicenow tags that could be used in address objects:
    #  os
    #  sys_class_name
    logging.info("Begin sync with firewall/panorama dynamic address objects")

    reg_list = []
    unreg_list = []

    if not no_delete:
        logging.info("Delete is allowed. Getting current dynamic addresses "
                      "from firewall/panorama for comparison")
        current_tags = device.get_all_registered_addresses()
        for reg_address in current_tags:
            ip, tag = reg_address
            tags_in_servicenow = next((sn_object for sn_object in objects if (sn_object['ip_address'] == ip and tag in sn_object.values())), None)
            if not tags_in_servicenow:
                unreg_list.append(reg_address)

    for address in objects:
        reg_list.append((address['ip_address'], "sn.class."+address['class']))
        reg_list.append((address['ip_address'], "sn.type."+address['superclass']))
        reg_list.append((address['ip_address'], "sn.os."+address['os']))

    device.update_dynamic_addresses(reg_list, unreg_list)


# main function
def main():

    parser = argparse.ArgumentParser(description='Sync ServiceNow assets to Palo Alto Networks objects')

    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv or -vvv for extra verbose)")
    parser.add_argument('-n', '--no-delete', action='store_true', default=False, help="Only add objects, do not delete objects")

    # Palo Alto Networks related arguments
    fw_group = parser.add_argument_group('Palo Alto Networks')
    fw_group.add_argument('fw_hostname', help="Hostname of firewall or Panorama")
    fw_group.add_argument('-P', '--fw-port', default="443", help="API port of Firewall or Panorama")
    fw_group.add_argument('-s', '--fw-vsys', default="vsys1", help="vsys on Firewall or Panorama")
    cred_group = fw_group.add_mutually_exclusive_group(required=True)
    cred_group.add_argument('-K', '--fw-apikey', help="API Key for Firewall or Panorama")
    cred_group.add_argument('-l', '--fw-creds', help="Credentials for Firewall or Panorama")

    # ServiceNow related arguments
    sn_group = parser.add_argument_group('ServiceNow')
    sn_group.add_argument('sn_fqdn', help="FQDN of ServiceNow hosted instance")
    sn_group.add_argument('sn_creds', help="ServiceNow credentials: username:password")

    args = parser.parse_args()

    ###
    ### Set up logger
    ###
    # Logging Levels
    # WARNING is 30
    # INFO is 20
    # DEBUG is 10
    if args.verbose is not None:
        logging_level = max(30 - (args.verbose * 10), logging.DEBUG)
        if logging_level == logging.DEBUG:
            logging_format = '%(levelname)s: %(name)s:%(message)s'
        else:
            logging_format = '%(levelname)s: %(message)s'
        logging.basicConfig(format=logging_format, level=logging_level)
    else:
        args.verbose = 0

    # get the list of assets from ServiceNow
    assets_json = retrieve_servicenow_asset_list(args.sn_creds.split(':')[0],
                                                args.sn_creds.split(':')[1],
                                                args.sn_fqdn)

    interesting_assets = parse_servicenow_assets(assets_json)

    logging.info("%d assets have a hostname and IP address" % len(interesting_assets))

    from pprint import pformat
    logging.debug("Assets found:  \n%s" % (pformat(interesting_assets),))

    logging.info("Preparing connection to firewall/panorama at %s" % args.fw_hostname)
    device = device.PanDevice(args.fw_hostname,
                                 args.fw_port,
                                 args.fw_creds.split(':')[0],
                                 args.fw_creds.split(':')[1]
                                 )

    #sync_address_objects(device, interesting_assets, args.no_delete)
    sync_dynamic_address_objects(device, interesting_assets, args.no_delete)

# Call the main() function to begin the program if not
# loaded as a module.
if __name__ == '__main__':
    main()
