#!/usr/bin/env/python
#
# configure_firewall_rules.py
#
# Iterates through rows of the user-specified CSV file, and configures the target Edges with the desired firewall rules
#
# Usage : configure_firewall_rules.py <file> --host <host> --enterprise <enterpriseId> [--operator] [--insecure]
#
# Options:
#   file              name of the csv file to read (see example_input.csv for sample format)
#   host              the VCO hostname (e.g. vcoXX-usca1.velocloud.net or 12.34.56.7)
#   -e enterprise     id of the target enterprise
#   --operator        authenticate as an operator user (defaults to True)
#   --insecure        when passed, tells the client to ignore SSL certificate verifcation errors (e.g. in a
#                     sandbox environment)
#
# Dependencies:
#   - The only library required to use this tool is the Python requests library, which can be installed with pip
#   - VC_USERNAME and VC_PASSWORD must be set as environment variables
#

import argparse
import csv
import os
import requests
import sys
import traceback

from copy import deepcopy
from ipaddress import IPv4Network

from client import VcoRequestManager

def get_env_or_abort(var):
    try:
        return os.environ[var]
    except IndexError:
        print("env.%s is not set. Aborting." % s)
    sys.exit(-1)

def get_template_rule(module):
    rules = module['data']['segments'][0]['outbound']
    return [rule for rule in rules if rule['name'] == 'AllowAny'][0]

def configure_rule(client, edge, row):

    # Fetch configuration stack

    method = 'edge/getEdgeConfigurationStack'
    params = {
        'enterpriseId': edge['enterpriseId'],
        'edgeId': edge['id']
    }
    stack = client.call_api(method, params)

    edge_specific_profile = stack[0]
    profile = stack[1]

    edge_firewall_module_id = None
    edge_firewall_module_data = None

    profile_firewall_module = [module for module in profile['modules'] if module['name'] == 'firewall'][0]

    # Get Edge firewall module (note that this may not exist for new Edges)

    tmp = [module for module in edge_specific_profile['modules'] if module['name'] == 'firewall']
    if len(tmp) > 0:
        edge_firewall_module_id = tmp[0]['id']
        edge_firewall_module_data = tmp[0]['data']
    else:

        # We need to create an Edge-specific firewall module instance if one doesn't already exist

        edge_firewall_module_data = deepcopy(profile_firewall_module['data'])

        method = 'configuration/insertConfigurationModule'
        params = {
            'enterpriseId': edge['enterpriseId'],
            'configurationId': edge_specific_profile['id'],
            'name': 'firewall',
            'data': edge_firewall_module_data
        }
        result = client.call_api(method, params)

        edge_firewall_module_id = result['id']


    # https://docs.python.org/3/library/ipaddress.html#ipaddress.ip_network
    network = IPv4Network('%s/%s' % (row['sourceIp'], row['sourcePrefix']), False)

    existing_rules = edge_firewall_module_data['segments'][0]['outbound']
    for rule in existing_rules:
        if rule['name'] == ':'.join([str(network),row['destIp'],row['destPort']]):
            print('\tRule already exists for %s on Edge %s, skipping...' % (rule['name'], edge['name']))
            return

    # Fetch template rule from the profile (this could also be hard-coded or stored in a file, conceivably)
    template_rule = None
    try:
        template_rule = get_template_rule(profile_firewall_module)
    except Exception as e:
        print("\tFailed to get template rule: " + str(e))
        return

    new_rule = deepcopy(template_rule)

    new_rule['name'] = ':'.join([str(network),row['destIp'],row['destPort']])

    if row['action'].lower() == 'allow':
        new_rule['action']['allow_or_deny'] = 'allow'
    elif row['action'].lower() == 'deny':
        new_rule['action']['allow_or_deny'] = 'deny'

    new_rule['match']['s_rule_type'] = 'prefix'
    new_rule['match']['sip'] = str(network.network_address)
    new_rule['match']['ssm'] = str(network.netmask)
    new_rule['match']['dip'] = row['destIp']
    new_rule['match']['dport_low'] = int(row['destPort'])
    new_rule['match']['dport_high'] = int(row['destPort'])

    if len(edge_firewall_module_data['segments']) == 0:
        edge_firewall_module_data['segments'].append({ 'outbound': [] }) 
    edge_firewall_module_data['segments'][0]['outbound'].append(new_rule)

    # Make update call

    method = 'configuration/updateConfigurationModule'
    params = {
        'enterpriseId': edge['enterpriseId'],
        'id': edge_firewall_module_id,
        '_update': {
            'data': edge_firewall_module_data
        }
    }
    client.call_api(method, params)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="name of the csv file to read")
    parser.add_argument("--host", default=os.environ.get("VC_HOSTNAME"),
                        help="vco hostname")
    parser.add_argument("-e", "--enterprise", type=int,
                        help="id of the target enterprise")
    parser.add_argument("--operator", action="store_true", default=False, help="login as operator")
    parser.add_argument("--insecure", action="store_true", help="ignore ssl cert warnings/errors")
    args = parser.parse_args()

    if args.insecure:
        from requests.packages.urllib3.exceptions import (
            InsecureRequestWarning,
            InsecurePlatformWarning,
            SNIMissingWarning
        )
        for warning in ( InsecureRequestWarning, InsecurePlatformWarning, SNIMissingWarning ):
            requests.packages.urllib3.disable_warnings(warning)

    # Initialize client, authenticate

    client = VcoRequestManager(args.host, verify_ssl=(not args.insecure)) 
    username = get_env_or_abort("VC_USERNAME")
    password = get_env_or_abort("VC_PASSWORD")

    try:
        client.authenticate(username, password, args.operator)
    except Exception as e:
        print("Encountered error while authenticating: " + str(e))
        sys.exit(-1)

    # Read CSV

    rules = None
    with open(args.file) as csvfile:
        rules = list(csv.DictReader(csvfile))

    # Get Edges

    edges = None
    method = 'enterprise/getEnterpriseEdges'
    params = { 'enterpriseId': args.enterprise }
    try:
        edges = client.call_api(method, params)
    except ApiException as e:
        print("Encountered API error in call to %s: %s" % (method, e))
        sys.exit(-1)

    for row in rules:
        edge = None
        try:
            edge = [e for e in edges if e['name'] == row['edgeName']][0]
        except IndexError:
            print("Skipping rule for Edge %s - no such Edge exists" % row['edgeName'])

        try:
            print('Configuring rule for Edge %s' % row['edgeName'])
            configure_rule(client, edge, row)
            print('Successfully applied rule to Edge %s' % row['edgeName'])
        except Exception as e:
            print("Failed to apply rule for Edge %s:" % row['edgeName'])
            traceback.print_exc()

if __name__ == "__main__":
    main()
