#!/usr/bin/python
from pdb import *
import subprocess
import sys
import json
import os

keystone_conf = "/etc/keystone/keystone.conf"
stored_passwd = "/var/lib/keystone/keystone.passwd"

def execute(cmd, die=False, echo=False):
    """ Executes a command 

    if die=True, script will exit(1) if command does not return 0
    if echo=True, output of command will be printed to stdout

    returns a tuple: (stdout, stderr, return code)
    """
    p = subprocess.Popen(cmd.split(" "),
                         stdout=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout=""
    stderr=""

    def print_line(l):
        if echo:
            print l.strip('\n')
            sys.stdout.flush()

    for l in iter(p.stdout.readline, ''):
        print_line(l)
        stdout += l
    for l in iter(p.stderr.readline, ''):
        print_line(l)
        stderr += l

    p.communicate()
    rc = p.returncode

    if die and rc != 0:
        error_out("ERROR: command %s return non-zero.\n" % cmd)
    return (stdout, stderr, rc)


def juju_log(msg):
    execute("juju-log \"%s\"" % msg)

def error_out(msg):
    juju_log("FATAL ERROR: %s" % msg)
    exit(1)

def setup_ppa(rel):
    """ Configure a PPA prior to installing.
    Currently, keystone-core only maintains a trunk PPA (unlike other
    subprojects that maintain one for milestone + milestone-proposed)
    Currently, supported options are 'trunk' or a custom PPA passed to config
    as 'ppa:someproject/someppa'
    """
    if rel == "trunk":
        ppa = "ppa:keystone-core/trunk"
    elif rel[:4] == "ppa:":
        ppa = rel
    else:
        error_out("Invalid keystone-release specified: %s" % rel)
    execute(("add-apt-repository -y %s" % ppa), die=True, echo=True)

def config_get():
    """ Obtain the units config via 'config-get' 
    Returns a dict representing current config.
    private-address and IP of the unit is also tacked on for
    convienence
    """
    output = execute("config-get --format json")[0]
    config = json.loads(output)
    # make sure no config element is blank after config-get
    for c in config.keys():
       if not config[c]:
            error_out("ERROR: Config option has no paramter: %s" % c)
    # tack on our private address and ip
    hostname = execute("unit-get private-address")[0].strip()
    ip = execute("dig +short %s" % hostname, die=True)[0].strip()
    config["hostname"] = hostname
    config["ip"] = ip
    return config

def relation_set(relation_data):
    """ calls relation-set for all key=values in dict """
    for k in relation_data:
        execute("relation-set %s=%s" % (k, relation_data[k]), die=True)

def relation_get(relation_data):
    """ Obtain all current relation data
    relation_data is a list of options to query from the relation
    Returns a k,v dict of the results. 
    Leave empty responses out of the results as they haven't yet been
    set on the other end. 
    Caller can then "len(results.keys()) == len(relation_data)" to find out if
    all relation values have been set on the other side
    """
    results = {}
    for r in relation_data:
        result = execute("relation-get %s" % r, die=True)[0].strip('\n')
        if result != "":
           results[r] = result
    return results

def keystone_conf_update(opt, val):
    """ Updates keystone.conf values 
    If option exists, it is reset to new value
    If it does not, it added to the top of the config file after the [DEFAULT]
    heading to keep it out of the paste deploy config
    """
    f = open(keystone_conf, "r+")
    orig = f.readlines()
    new = ""
    found = False
    for l in orig:
        if l.split(' ')[0] == opt:
            juju_log("Updating %s, setting %s = %s" % (keystone_conf, opt, val))
            new += "%s = %s\n" % (opt, val)
            found  = True
        else:
            new += l
    new = new.split('\n')
    # insert a new value at the top of the file, after the 'DEFAULT' header so
    # as not to muck up paste deploy configuration later in the file 
    if not found:
        juju_log("Adding new config option %s = %s" % (opt, val))
        header = new.index("[DEFAULT]")
        new.insert((header+1), "%s = %s" % (opt, val))
    f.seek(0)
    f.truncate()
    for l in new:
        f.write("%s\n" % l)
    f.close

def create_service_entry(manager, service_name, service_type,
                         service_desc, owner=None):
    """ Add a new service entry to keystone if one does not already exist """
    for service in manager.api.list_services():
        if service[1] == service_name:
            juju_log("Service entry for '%s' already exists." % service_name)
            return
    manager.api.add_service(name=service_name,
                            type=service_type,
                            desc=service_desc, owner_id=owner)
    juju_log("Created new service entry '%s'" % service_name)

def create_endpoint_template(manager, region, service,  public_url,
                             admin_url, internal_url):
    """ Create a new endpoint template for service if one does not already
        exist matching name *and* region """
    for endpoint in manager.api.list_endpoint_templates():
        if endpoint[1] == service and  endpoint[3] == region:
            juju_log("Endpoint template already exists for '%s' in '%s'"
                      % (service, region))
            return
    manager.api.add_endpoint_template(region=region, service=service,
                             public_url=public_url, admin_url=admin_url,
                             internal_url=internal_url, enabled=1, is_global=1,
                             version_id=None, version_list=None,
                             version_info=None)
    juju_log("Created new endpoint template for '%s' in '%s'"
              % (region, service))

def create_tenant(manager, name):
    """ creates a tenant if it does not already exist """
    tenants = manager.api.list_tenants()
    if not tenants or name not in map(lambda t: t[1], tenants):
        manager.api.add_tenant(name=name)
        juju_log("Created new tenant: %s" % name)
        return
    juju_log("Tenant '%s' already exists." % name)

def create_user(manager, name, password, tenant):
    """ creates a user if it doesn't already exist, as a member of tenant """
    users = manager.api.list_users()
    if not users or name not in map(lambda u: u[1], users):
        manager.api.add_user(name=name, password=password, tenant=tenant)
        juju_log("Created new user '%s'" % name)
        return
    juju_log("A user named '%s' already exists" % name)

def create_role(manager, name, user):
    """ creates a role if it doesn't already exist. grants role to user """
    roles = manager.api.list_roles()
    if not roles or name not in map(lambda r: r[1], roles):
        manager.api.add_role(name=name)
        juju_log("Created new role '%s'" % name)
    else:
        juju_log("A role named '%s' already exists" % name)
    # NOTE: There does not seem to be any way of querying current role asignment
    manager.api.grant_role(name, user)
    juju_log("Granted role '%s' to '%s'" % (name, user))

def generate_admin_token(manager, config):
    """ generate and add an admin token """
    if config["admin-token"] == None:
        import random
        token = random.randrange(1000000000000, 9999999999999)
    else:
        return config["admin-token"]
    manager.api.add_token(token, config["admin-user"], "admin", config["token-expiry"])
    juju_log("Generated and added new random admin token.")
    return token

def ensure_initial_admin(config):
    """ Ensures the minimum admin stuff exists in whatever database we're using.
        This and the helper functions it calls are meant to be idempotent and
        run during install as well as during db-changed.  This will maintain
        the admin tenant, user, role, service entry and endpoint across every
        datastore we might use. 
        TODO: Possibly migrate data from one backend to another after it
        changes?
    """
    import manager
    create_tenant(manager, "admin")

    passwd = ""
    if config["admin-password"] != "None":
        passwd = config["admin-password"]
    elif os.path.isfile(stored_passwd):
        juju_log("Loading stored passwd from %s" % stored_passwd)
        passwd = open(stored_passwd, 'r').readline().strip('\n')
    if passwd == "":
        juju_log("Generating new passwd for user: %s" % config["admin-user"])
        passwd = execute("pwgen -c 16 1", die=True)[0]
        open(stored_passwd, 'w+').writelines("%s\n" % passwd)

    create_user(manager, config["admin-user"], passwd, tenant="admin")
    create_role(manager, "Admin", config["admin-user"])
    create_role(manager, "KeystoneAdmin", config["admin-user"])
    create_role(manager, "KeystoneServiceAdmin", config["admin-user"])
    create_service_entry(manager, "keystone",
                         "identity", "Keystone Identity Service")
    # if we are using a shared admin-token, create it with with rest of initial
    # admin credentials.
    if config["admin-token"]:
        juju_log("Creating pre-configured, shared admin-token.")
        try:
            manager.api.add_token(config["admin-token"], config["admin-uesr"],
                                  "admin", config["token-expiry"])
        except:
            juju_log("Could not create admin token.  Already exists?")

    # following documentation here, perhaps we should be using juju
    # public/private addresses for public/internal urls.
    public_url = "http://%s:%s/v2.0" % (config["ip"], config["service-port"])
    admin_url = "http://%s:%s/v2.0" % (config["ip"], config["admin-port"])
    internal_url = "http://%s:%s/v2.0" % (config["ip"], config["service-port"])
    create_endpoint_template(manager, "RegionOne", "keystone", public_url,
                             admin_url, internal_url)
