#!/usr/bin/python
import subprocess
import sys
import json
import os
import time

from lib.openstack_common import *

keystone_conf = "/etc/keystone/keystone.conf"
stored_passwd = "/var/lib/keystone/keystone.passwd"
stored_token = "/var/lib/keystone/keystone.token"

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

def relation_ids(relation_name=None):
    j = execute('relation-ids --format=json %s' % relation_name)[0]
    return json.loads(j)

def relation_list(relation_id=None):
    cmd = 'relation-list --format=json'
    if relation_id:
        cmd += ' -r %s' % relation_id
    j = execute(cmd)[0]
    return json.loads(j)

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

def relation_get_dict(relation_id=None, remote_unit=None):
    """Obtain all relation data as dict by way of JSON"""
    cmd = 'relation-get --format=json'
    if relation_id:
        cmd += ' -r %s' % relation_id
    if remote_unit:
        remote_unit_orig = os.getenv('JUJU_REMOTE_UNIT', None)
        os.environ['JUJU_REMOTE_UNIT'] = remote_unit
    j = execute(cmd, die=True)[0]
    if remote_unit and remote_unit_orig:
        os.environ['JUJU_REMOTE_UNIT'] = remote_unit_orig
    d = json.loads(j)
    settings = {}
    # convert unicode to strings
    for k, v in d.iteritems():
        settings[str(k)] = str(v)
    return settings

def set_admin_token(admin_token):
    """Set admin token according to deployment config or use a randomly
       generated token if none is specified (default).
    """
    if admin_token != 'None':
        juju_log('Configuring Keystone to use a pre-configured admin token.')
        token = admin_token
    else:
        juju_log('Configuring Keystone to use a random admin token.')
        if os.path.isfile(stored_token):
            msg = 'Loading a previously generated admin token from %s' % stored_token
            juju_log(msg)
            f = open(stored_token, 'r')
            token = f.read().strip()
            f.close()
        else:
            token = execute('pwgen -c 32 1', die=True)[0].strip()
            out = open(stored_token, 'w')
            out.write('%s\n' % token)
            out.close()
    update_config_block('DEFAULT', admin_token=token)

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

def create_endpoint_template(region, service,  publicurl, adminurl,
                             internalurl):
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

            up_to_date = True
            for k in ['publicurl', 'adminurl', 'internalurl']:
                if ep[k] != locals()[k]:
                    up_to_date = False

            if up_to_date:
                return
            else:
                # delete endpoint and recreate if endpoint urls need updating.
                juju_log("Updating endpoint template with new endpoint urls.")
                manager.api.endpoints.delete(ep['id'])

    manager.api.endpoints.create(region=region,
                                 service_id=service_id,
                                 publicurl=publicurl,
                                 adminurl=adminurl,
                                 internalurl=internalurl)
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

    grant_role(user, name, tenant)

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
    update_user_password(config['admin-user'], passwd)
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

def update_user_password(username, password):
    import manager
    manager = manager.KeystoneManager(endpoint='http://localhost:35357/v2.0/',
                                      token=get_admin_token())
    juju_log("Updating password for user '%s'" % username)

    user_id = manager.resolve_user_id(username)
    if user_id is None:
        error_out("Could not resolve user id for '%s'" % username)

    manager.api.users.update_password(user=user_id, password=password)
    juju_log("Successfully updated password for user '%s'" % username)


def do_openstack_upgrade(install_src, packages):
    '''Upgrade packages from a given install src.'''

    config = config_get()
    old_vers = get_os_codename_package('keystone')
    new_vers = get_os_codename_install_source(install_src)

    juju_log("Beginning Keystone upgrade: %s -> %s" % (old_vers, new_vers))

    # Backup previous config.
    juju_log("Backing up contents of /etc/keystone.")
    stamp = time.strftime('%Y%m%d%H%M')
    cmd = 'tar -pcf /var/lib/juju/keystone-backup-%s.tar /etc/keystone' % stamp
    execute(cmd, die=True, echo=True)

    configure_installation_source(install_src)
    execute('apt-get update', die=True, echo=True)
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    cmd = 'apt-get --option Dpkg::Options::=--force-confnew -y '\
          'install %s' % packages
    execute(cmd, echo=True, die=True)

    # we have new, fresh config files that need updating.
    # set the admin token, which is still stored in config.
    set_admin_token(config['admin-token'])

    # set the sql connection string if a shared-db relation is found.
    ids = relation_ids(relation_name='shared-db')

    if ids:
        for id in ids:
            for unit in relation_list(id):
                juju_log('Configuring new keystone.conf for datbase access '\
                         'on existing database relation to %s' % unit)
                relation_data = relation_get_dict(relation_id=id,
                                                  remote_unit=unit)

                update_config_block('sql', connection="mysql://%s:%s@%s/%s" %
                                        (config["database-user"],
                                         relation_data["password"],
                                         relation_data["private-address"],
                                         config["database"]))

    juju_log('Running database migrations for %s' % new_vers)
    execute('service keystone stop', echo=True)
    execute('keystone-manage db_sync', echo=True, die=True)
    execute('service keystone start', echo=True)
    time.sleep(5)
    juju_log('Completed Keystone upgrade: %s -> %s' % (old_vers, new_vers))
