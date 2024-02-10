#!/usr/bin/env python3
import requests
import json
import os
import time
import argparse
import subprocess


"""
provisioner.py: script to provison a VPS VM, create DNS entires, and boostrap
the core packages to run the VPS system.
"""

red = lambda text: f"\033[0;31m{text}\033[0m"

API_KEY=os.environ['VULTR_API_KEY']
VERBOSE=0
def spinner():
    spins = [
        "/",
        "-",
        "\\",
        "|",
        "/",
        "-",
        "\\",
        "|"
    ]

    while True:
        for i in spins:
            yield i

def test_key(target_addr: str):

    cmd = f"ssh -o 'StrictHostKeyChecking no' root@{target_addr} hostname"
    r = subprocess.run(cmd, shell = True)
    try:
        while r.returncode != 0:
            r = subprocess.run(cmd, shell = True)
        return True
    except KeyboardInterrupt as e:
        print(f"Got keyboard interrupt during {cmd}. {red('SSH not tested or failed.')}")
        return False

def get_master_key_id(name: str = "master"):
    keys = make_request("ssh-keys", blob = {})
    for ob in keys['ssh_keys']:
        if ob['name'] == name:
            return ob['id']


def make_request(*endpoints, blob: dict, kind = "get", returns = True):
    """
    Send a request to Vultr API
    """
    if not hasattr(requests, kind):
        raise Exception(f"{kind} not a valid HTTP request type")
    url = "https://api.vultr.com/v2"
    for endpoint in endpoints:
        url += "/" + endpoint
    if VERBOSE: print(f"URL: {url}")
    headers = {
            "Authorization": f"Bearer {API_KEY}"
            }

    if hasattr(requests, kind):
        cb = getattr(requests, kind)
    else:
        print(red(f"Failed: kind: {kind} not a valid HTTP request type."))
        quit(1)
    ret = cb(url, json = blob, headers = headers)
    try:
        if VERBOSE: print(json.dumps(ret.json(), indent = 4))
        if returns:
            return ret.json()
        else:
            return {}
    except json.JSONDecodeError as e:
        print(e)
        return {}


def watch_instance(blob: dict, target_state: str):
    """
    Watch the instance creatoion state until key == value.
    """

    instance_id = blob['instance']['id']
    main_ip = blob['instance']['main_ip']
    status = blob['instance']['server_status']
    default_password = blob.get('default_password')

    spin = spinner()
    i = 0
    while status != "ok":
        time.sleep(1)
        i += 1
        instances = get_instances()['instances']
        for instance in instances:
            if instance['id'] == instance_id:
                status = instance['server_status']
                main_ip = instance['main_ip']
                n = next(spin)
                pws = "Yes" if default_password else "No"
                print(
                    f"{n} Waiting for: {instance['label']} to have state: {target_state} (current state: {status}) (PW: {pws}) ({i}/unlimited)\r",
                    end = "",
                    flush = True)
                pw = instance.get('default_password')
                if pw and not default_password:
                    default_password = instance.get('default_password')

    test_key(main_ip)


def list_dns_entries(domain_name: str):
    """
    Get a list of all domain name entries
    """
    req = make_request("domains", domain_name, "records", blob = {})
    return req


def create_record(domain_name,
                  record_kind,
                  record_name,
                  record_value,
                  ttl
                  ):
    """
    Create a DNS entry using the VULTR API
    """

    current_recordes = list_dns_entries(domain_name)
    current = False
    for record in current_recordes['records']:
        if record['name'] == record_name:
            current = record['id']



    endpoints = ["domains",
                 domain_name,
                 "records"]

    key_id = get_master_key_id()
    kind = "post"
    json_blob = {
        "name": record_name,
        "type": record_kind,
        "data": record_value,
        "ttl": ttl,
        "priority": 0,
        "sshkey_id": key_id
    }

    if current:
        endpoints = ["domains", domain_name, "records", current]
        kind = "patch"
        returns = False
        print(f"Have current DNS record with ID: {current}. Updating.")
    else:
        print(f"Creating DNS entry for {json_blob['name']}")
        returns = True
    make_request(*endpoints, blob = json_blob, kind = kind, returns = returns )

def get_instances():
    return make_request("instances", blob = dict())

def get_os_ids(selector: str = None):
    blob = make_request("os", blob = dict())

    kinds = {}
    for os in blob['os']:
        if not os['family'] in kinds.keys():
            kinds[os['family']] = {}
        kinds[os['family']][os['name']] = os['id']

    if selector:
        return kinds.get(selector)
    else:
        return kinds

def get_ssh_keys():
    return make_request("ssh-keys", blob = dict())

def get_ssh_key_id(name):
    blob = make_request("ssh-keys", blob = dict())
    for key in blob['ssh_keys']:
        if key['name'] == name:
            return key['id']


def pretty_print_instances():
    instances = get_instances()
    for entry in instances['instances']:
        print("{:20}: {:20} {:20}".format("Label", entry['label'], entry['id']))
        print("{:20}: {:20}".format("IP", entry['main_ip']))

def create_instance(
        hostname,
        label,
        os_id,
        enable_ipv6: bool = False,

        region: str = "lax"
):
    ob = {
        "region": region,
        "plan": "vc2-1c-1gb",
        "label": label,
        "os_id": os_id or 2104,
        "backups": "disabled",
        "enable_ipv6": False,
        "hostname": hostname,
        "tags": []
    }


    ret = make_request("instances", blob = ob, kind = "post")

    if VERBOSE: print(json.dumps(ret, indent = 4))
    print(f"Created instance: {label}.")
    watch_instance(ret, target_state = "ok")
    return ret

def manage_instance_state(name: str, action: str):
    if not action in ["reboot", "stop", "start"]:
        raise Exception(f"Failed: action must be one of: reboot, stop, restart")

    for instance in get_instances()['instances']:
        if instance['label'] == name:
            make_request("instances", instance['id'], action, blob = {}, kind = "post")
            print(f"{action.capitalize()}ed instance {name}")
            break
    else:
        print(f"Failed: no instance named {name} to reboot!")


def delete_instance(name: str):
    for instance in get_instances()['instances']:
        if instance['label'] == name:
            make_request("instances", instance['id'], blob = {}, kind = "delete", returns = False)
            print(f"Deleted instance {instance['label']}")
            break
    else:
        print(f"Failed: no instance named {name} to delete!")
        return False
    return True

def reinstall_instance(name: str):
    for instance in get_instances()['instances']:
        if instance['label'] == name:
            id =  instance['id']
            blob = { "hostname": instance['hostname']}
            make_request("instances", id, "reinstall", blob = blob, kind = "post")
            print(f"Reinstalling instance {instance['label']}")
    else:
        print(f"No valid instance named {name} found. Cannot reinstall.")
        return False

parser = argparse.ArgumentParser()
parser.add_argument("action", action = "store")
parser.add_argument("target", action = "store")
parser.add_argument(
    "-d", "--domain", action = "store", default = "slovendor.com"
)
parser.add_argument(
    "-n", "--name", action = "store", help = "Name of instance"
)

parser.add_argument(
    "-V", "--value", action = "store", help = "Value for DNS entry."
)

parser.add_argument("-K", "--kind", help = "DNS record kind", default = "A")

parser.add_argument(
    "-k", "--key", action = "store", help = "SSH key to use"
)

parser.add_argument(
    "-o", "--os-id", action = "store"
)

parser.add_argument("-s", "--subdomain", action = "store")

parser.add_argument(
    "--no-dns", action = "store_true", default = False
)
parser.add_argument(
    "--no-provision", action = "store_true", default = False
)

parser.add_argument(
    "-v", "--verbose", action = "store_true", default = False
)

parser.add_argument(
    "-y", "--assume-yes", action = "store_true", default = False
)

if __name__ == "__main__":
    args = parser.parse_args()
    dns_needs = needed = {
                "subdomain": args.subdomain,
                "domain": args.domain,
                "kind": args.kind,
                "value": args.value
            }
    instance_needs = {
                "subdomain": args.subdomain,
                "domain": args.domain,
                "os_id": args.os_id
            }

    def check_dns_needs():
        for k, v in dns_needs.items():
            if not v:
                print(f"Need command line flag for:  {k} to manage DNS")
                quit(1)

    def check_instance_needs():
        for k, v in instance_needs.items():
            if not v:
                print(f"Need command line flag for: {k} to manage instances.")
                quit(1)

    if args.verbose:
        VERBOSE = 1
    if args.action == "get":
        if args.target == "dns":
            ob = list_dns_entries("slovendor.com")
            for entry in ob['records']:
                if entry.get('name'):
                    print(entry['name'], entry['type'])
        elif args.target == "instances":
            pretty_print_instances()
        elif args.target in [ "oses", "osids" ]:
            print(json.dumps(get_os_ids(), indent = 4))

    elif args.action == "create":
        if args.target == "dns":
            check_dns_needs()
            create_record(args.domain, args.kind, args.subdomain, args.value, 600)

        if args.target == "instance":
            check_instance_needs()
            if not args.name:
                args.name = "{args.subdomain}.args.domain}"
                print(f"Warning: using default name '{args.name}")
            create_instance(args.subdomain + "." + args.domain,
                            args.name,
                            args.os_id,
                            False)

    elif args.action == "provision":
        check_instance_needs()
        check_dns_needs()
        instance = create_instance(args.subdomain + "." + args.domain,
                        args.name,
                        args.os_id,
                        False)

        main_ip = instance['main_ip']
        create_record(args.domain, args.kind, args.subdomain, main_ip, 600)


    elif args.action in ["stop", "start", "reboot"]  and args.target:
        manage_instance_state(args.target, args.action)

    elif args.action == "delete" and args.target:
        if not args.assume_yes and not input(f"Really delete instance: {args.target}?").upper() in ["YES", "Y"]:
            print(f"Not deleting instance {args.target}")
        else:
            delete_instance(args.target)
    elif args.action == "reinstall" and args.target:
        reinstall_instance(args.target)
    else:
        print(f"Failed: {args.action} {args.target} not understood with given.")
