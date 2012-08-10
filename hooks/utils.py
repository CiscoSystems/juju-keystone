#!/usr/bin/python
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
    elif rel[:3] == "deb":
        l = len(rel.split('|'))
        if l ==  2:
            ppa, key = rel.split('|')
            juju_log("Importing PPA key from keyserver for %s" % ppa)
            cmd = "apt-key adv --keyserver keyserver.ubuntu.com " \
                  "--recv-keys %s" % key
            execute(cmd, echo=True)
        elif l == 1:
            ppa = rel
        else:
            error_out("Invalid keystone-release: %s" % rel)
    else:
        error_out("Invalid keystone-release specified: %s" % rel)
    subprocess.call(["add-apt-repository", "-y", ppa])

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
    config["hostname"] = execute("unit-get private-address")[0].strip()
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

def relation_get_dict():
    """Obtain all relation data as dict by way of JSON"""
    j = execute('relation-get --format=json', die=True)[0]
    d = json.loads(j)
    settings = {}
    # convert unicode to strings
    for k, v in d.iteritems():
        settings[str(k)] = str(v)
    return settings

def get_admin_token():
    """Temporary utility to grab the admin token as configured in
       keystone.conf
    """
    f = open(keystone_conf, 'r+')
    for l in open(keystone_conf, 'r+').readlines():
        if l.split(' ')[0] == 'admin_token':
            try:
                return l.split('=')[1].strip()
            except:
                error_out('Could not parse admin_token line from %s' %
                          keystone_conf)
    error_out('Could not find admin_token line in %s' % keystone_conf)

def update_config_block(block, **kwargs):
    """ Updates keystone.conf blocks given kwargs.
    Can be used to update driver settings for a particular backend,
    setting the sql connection, etc. 
    
    Parses block heading as '[block]'
    
    If block does not exist, a new block will be created at end of file with
    given kwargs
    """
    f = open(keystone_conf, "r+")
    orig = f.readlines()
    new = []
    found_block = ""
    heading = "[%s]\n" % block

    lines = len(orig)
    ln = 0

    def update_block(block):
        for k, v in kwargs.iteritems():
            for l in block:
                if l.strip().split(" ")[0] == k:
                    block[block.index(l)] = "%s = %s\n" % (k, v)
                    return
            block.append('%s = %s\n' % (k, v))
            block.append('\n')

    try:
        found = False
        while ln < lines:
            if orig[ln] != heading:
                new.append(orig[ln])
                ln += 1
            else:
                new.append(orig[ln])
                ln += 1
                block = []
                while orig[ln].strip() != '':
                    block.append(orig[ln])
                    ln += 1
                update_block(block)
                new += block
                found = True

        if not found:
            if new[(len(new) - 1)].strip() != '':
                new.append('\n')
            new.append('%s' % heading)
            for k, v in kwargs.iteritems():
                new.append('%s = %s\n' % (k, v))
            new.append('\n')
    except:
        error_out('Error while attempting to update config block. '\
                  'Refusing to overwite existing config.')

        return

    # backup original config
    backup = open(keystone_conf + '.juju-back', 'w+')
    for l in orig:
        backup.write(l)
    backup.close()

    # update config
    f.seek(0)
    f.truncate()
    for l in new:
        f.write(l)


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

def create_service_entry(service_name, service_type, service_desc, owner=None):
    """ Add a new service entry to keystone if one does not already exist """
    import manager
    manager = manager.KeystoneManager(endpoint='http://localhost:35357/v2.0/',
                                      token=get_admin_token())
    for service in [s._info for s in manager.api.services.list()]:
        if service['name'] == service_name:
            juju_log("Service entry for '%s' already exists." % service_name)
            return
    manager.api.services.create(name=service_name,
                                service_type=service_type,
                                description=service_desc)
    juju_log("Created new service entry '%s'" % service_name)

def create_endpoint_template(region, service,  public_url, admin_url,
                             internal_url):
    """ Create a new endpoint template for service if one does not already
        exist matching name *and* region """
    import manager
    manager = manager.KeystoneManager(endpoint='http://localhost:35357/v2.0/',
                                      token=get_admin_token())
    service_id = manager.resolve_service_id(service)
    for ep in [e._info for e in manager.api.endpoints.list()]:
        if ep['service_id'] == service_id and ep['region'] == region:
            juju_log("Endpoint template already exists for '%s' in '%s'"
                      % (service, region))
            return

    manager.api.endpoints.create(region=region,
                                 service_id=service_id,
                                 publicurl=public_url,
                                 adminurl=admin_url,
                                 internalurl=internal_url)
    juju_log("Created new endpoint template for '%s' in '%s'" %
                (region, service))

def create_tenant(name):
    """ creates a tenant if it does not already exist """
    import manager
    manager = manager.KeystoneManager(endpoint='http://localhost:35357/v2.0/',
                                      token=get_admin_token())
    tenants = [t._info for t in manager.api.tenants.list()]
    if not tenants or name not in [t['name'] for t in tenants]:
        manager.api.tenants.create(tenant_name=name,
                                   description='Created by Juju')
        juju_log("Created new tenant: %s" % name)
        return
    juju_log("Tenant '%s' already exists." % name)

def create_user(name, password, tenant):
    """ creates a user if it doesn't already exist, as a member of tenant """
    import manager
    manager = manager.KeystoneManager(endpoint='http://localhost:35357/v2.0/',
                                      token=get_admin_token())
    users = [u._info for u in manager.api.users.list()]
    if not users or name not in [u['name'] for u in users]:
        tenant_id = manager.resolve_tenant_id(tenant)
        if not tenant_id:
            error_out('Could not resolve tenant_id for tenant %s' % tenant)
        manager.api.users.create(name=name,
                                 password=password,
                                 email='juju@localhost',
                                 tenant_id=tenant_id)
        juju_log("Created new user '%s' pw: %s tenant: %s" % (name, password, tenant_id))
        return
    juju_log("A user named '%s' already exists" % name)

def create_role(name, user, tenant):
    """ creates a role if it doesn't already exist. grants role to user """
    import manager
    manager = manager.KeystoneManager(endpoint='http://localhost:35357/v2.0/',
                                      token=get_admin_token())
    roles = [r._info for r in manager.api.roles.list()]
    if not roles or name not in [r['name'] for r in roles]:
        manager.api.roles.create(name=name)
        juju_log("Created new role '%s'" % name)
    else:
        juju_log("A role named '%s' already exists" % name)

    # NOTE(adam_g): Keystone client requires id's for add_user_role, not names
    user_id = manager.resolve_user_id(user)
    role_id = manager.resolve_role_id(name)
    tenant_id = manager.resolve_tenant_id(tenant)

    if None in [user_id, role_id, tenant_id]:
        error_out("Could not resolve [user_id, role_id, tenant_id]" %
                   [user_id, role_id, tenant_id])

    manager.api.roles.add_user_role(user=user_id,
                                    role=role_id,
                                    tenant=tenant_id)
    juju_log("Granted role '%s' to '%s'" % (name, user))

def grant_role(user, role, tenant):
    """grant user+tenant a specific role"""
    import manager
    manager = manager.KeystoneManager(endpoint='http://localhost:35357/v2.0/',
                                      token=get_admin_token())
    juju_log("Granting user '%s' role '%s' on tenant '%s'" %\
                (user, role, tenant))
    user_id = manager.resolve_user_id(user)
    role_id = manager.resolve_role_id(role)
    tenant_id = manager.resolve_tenant_id(tenant)

    cur_roles =  manager.api.roles.roles_for_user(user_id, tenant_id)
    if not cur_roles or role_id not in [r.id for r in cur_roles]:
        manager.api.roles.add_user_role(user=user_id,
                                        role=role_id,
                                        tenant=tenant_id)
        juju_log("Granted user '%s' role '%s' on tenant '%s'" %\
                    (user, role, tenant))
    else:
        juju_log("User '%s' already has role '%s' on tenant '%s'" %\
                    (user, role, tenant))

def generate_admin_token(config):
    """ generate and add an admin token """
    import manager
    manager = manager.KeystoneManager(endpoint='http://localhost:35357/v2.0/',
                                      token='ADMIN')
    if config["admin-token"] == "None":
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
    create_tenant("admin")
    create_tenant(config["service-tenant"])
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

    create_user(config['admin-user'], passwd, tenant='admin')
    create_role(config['admin-role'], config['admin-user'], 'admin')
    # TODO(adam_g): The following roles are likely not needed since redux merge
    create_role("KeystoneAdmin", config["admin-user"], 'admin')
    create_role("KeystoneServiceAdmin", config["admin-user"], 'admin')
    create_service_entry("keystone", "identity", "Keystone Identity Service")
    # following documentation here, perhaps we should be using juju
    # public/private addresses for public/internal urls.
    public_url = "http://%s:%s/v2.0" % (config["hostname"], config["service-port"])
    admin_url = "http://%s:%s/v2.0" % (config["hostname"], config["admin-port"])
    internal_url = "http://%s:%s/v2.0" % (config["hostname"], config["service-port"])
    create_endpoint_template("RegionOne", "keystone", public_url,
                             admin_url, internal_url)
