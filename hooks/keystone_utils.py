#!/usr/bin/python
import ConfigParser
import sys
import json
import time
import subprocess
import os

from lib.openstack_common import(
    get_os_codename_install_source,
    get_os_codename_package,
    error_out,
    configure_installation_source
    )

import keystone_ssl as ssl
import lib.unison as unison
import lib.utils as utils
import lib.cluster_utils as cluster


keystone_conf = "/etc/keystone/keystone.conf"
stored_passwd = "/var/lib/keystone/keystone.passwd"
stored_token = "/var/lib/keystone/keystone.token"
SERVICE_PASSWD_PATH = '/var/lib/keystone/services.passwd'

SSL_DIR = '/var/lib/keystone/juju_ssl/'
SSL_CA_NAME = 'Ubuntu Cloud'
CLUSTER_RES = 'res_ks_vip'
SSH_USER = 'juju_keystone'


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
    stdout = ""
    stderr = ""

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
    config["hostname"] = utils.unit_get('private-address')
    return config


@utils.cached
def get_local_endpoint():
    """ Returns the URL for the local end-point bypassing haproxy/ssl """
    local_endpoint = 'http://localhost:{}/v2.0/'.format(
        cluster.determine_api_port(utils.config_get('admin-port'))
        )
    return local_endpoint


def set_admin_token(admin_token):
    """Set admin token according to deployment config or use a randomly
       generated token if none is specified (default).
    """
    if admin_token != 'None':
        utils.juju_log('INFO',
                       'Configuring Keystone to use'
                       ' a pre-configured admin token.')
        token = admin_token
    else:
        utils.juju_log('INFO',
                       'Configuring Keystone to use a random admin token.')
        if os.path.isfile(stored_token):
            msg = 'Loading a previously generated' \
                  ' admin token from %s' % stored_token
            utils.juju_log('INFO', msg)
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
    with open(keystone_conf, 'r') as f:
        for l in f.readlines():
            if l.split(' ')[0] == 'admin_token':
                try:
                    return l.split('=')[1].strip()
                except:
                    error_out('Could not parse admin_token line from %s' %
                              keystone_conf)
    error_out('Could not find admin_token line in %s' % keystone_conf)


def update_config_block(section, **kwargs):
    """ Updates keystone.conf blocks given kwargs.
    Update a config setting in a specific setting of a config
    file (/etc/keystone/keystone.conf, by default)
    """
    if 'file' in kwargs:
        conf_file = kwargs['file']
        del kwargs['file']
    else:
        conf_file = keystone_conf
    config = ConfigParser.RawConfigParser()
    config.read(conf_file)

    if section != 'DEFAULT' and not config.has_section(section):
        config.add_section(section)

    for k, v in kwargs.iteritems():
        config.set(section, k, v)
    with open(conf_file, 'wb') as out:
        config.write(out)


def create_service_entry(service_name, service_type, service_desc, owner=None):
    """ Add a new service entry to keystone if one does not already exist """
    import manager
    manager = manager.KeystoneManager(endpoint=get_local_endpoint(),
                                      token=get_admin_token())
    for service in [s._info for s in manager.api.services.list()]:
        if service['name'] == service_name:
            utils.juju_log('INFO',
                           "Service entry for '%s' already exists." % \
                           service_name)
            return
    manager.api.services.create(name=service_name,
                                service_type=service_type,
                                description=service_desc)
    utils.juju_log('INFO', "Created new service entry '%s'" % service_name)


def create_endpoint_template(region, service,  publicurl, adminurl,
                             internalurl):
    """ Create a new endpoint template for service if one does not already
        exist matching name *and* region """
    import manager
    manager = manager.KeystoneManager(endpoint=get_local_endpoint(),
                                      token=get_admin_token())
    service_id = manager.resolve_service_id(service)
    for ep in [e._info for e in manager.api.endpoints.list()]:
        if ep['service_id'] == service_id and ep['region'] == region:
            utils.juju_log('INFO',
                           "Endpoint template already exists for '%s' in '%s'"
                           % (service, region))

            up_to_date = True
            for k in ['publicurl', 'adminurl', 'internalurl']:
                if ep[k] != locals()[k]:
                    up_to_date = False

            if up_to_date:
                return
            else:
                # delete endpoint and recreate if endpoint urls need updating.
                utils.juju_log('INFO',
                               "Updating endpoint template with"
                               " new endpoint urls.")
                manager.api.endpoints.delete(ep['id'])

    manager.api.endpoints.create(region=region,
                                 service_id=service_id,
                                 publicurl=publicurl,
                                 adminurl=adminurl,
                                 internalurl=internalurl)
    utils.juju_log('INFO', "Created new endpoint template for '%s' in '%s'" %
                   (region, service))


def create_tenant(name):
    """ creates a tenant if it does not already exist """
    import manager
    manager = manager.KeystoneManager(endpoint=get_local_endpoint(),
                                      token=get_admin_token())
    tenants = [t._info for t in manager.api.tenants.list()]
    if not tenants or name not in [t['name'] for t in tenants]:
        manager.api.tenants.create(tenant_name=name,
                                   description='Created by Juju')
        utils.juju_log('INFO', "Created new tenant: %s" % name)
        return
    utils.juju_log('INFO', "Tenant '%s' already exists." % name)


def create_user(name, password, tenant):
    """ creates a user if it doesn't already exist, as a member of tenant """
    import manager
    manager = manager.KeystoneManager(endpoint=get_local_endpoint()(),
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
        utils.juju_log('INFO', "Created new user '%s' tenant: %s" % \
                       (name, tenant_id))
        return
    utils.juju_log('INFO', "A user named '%s' already exists" % name)


def create_role(name, user=None, tenant=None):
    """ creates a role if it doesn't already exist. grants role to user """
    import manager
    manager = manager.KeystoneManager(endpoint=get_local_endpoint(),
                                      token=get_admin_token())
    roles = [r._info for r in manager.api.roles.list()]
    if not roles or name not in [r['name'] for r in roles]:
        manager.api.roles.create(name=name)
        utils.juju_log('INFO', "Created new role '%s'" % name)
    else:
        utils.juju_log('INFO', "A role named '%s' already exists" % name)

    if not user and not tenant:
        return

    # NOTE(adam_g): Keystone client requires id's for add_user_role, not names
    user_id = manager.resolve_user_id(user)
    role_id = manager.resolve_role_id(name)
    tenant_id = manager.resolve_tenant_id(tenant)

    if None in [user_id, role_id, tenant_id]:
        error_out("Could not resolve [%s, %s, %s]" %
                   (user_id, role_id, tenant_id))

    grant_role(user, name, tenant)


def grant_role(user, role, tenant):
    """grant user+tenant a specific role"""
    import manager
    manager = manager.KeystoneManager(endpoint=get_local_endpoint(),
                                      token=get_admin_token())
    utils.juju_log('INFO', "Granting user '%s' role '%s' on tenant '%s'" % \
                   (user, role, tenant))
    user_id = manager.resolve_user_id(user)
    role_id = manager.resolve_role_id(role)
    tenant_id = manager.resolve_tenant_id(tenant)

    cur_roles = manager.api.roles.roles_for_user(user_id, tenant_id)
    if not cur_roles or role_id not in [r.id for r in cur_roles]:
        manager.api.roles.add_user_role(user=user_id,
                                        role=role_id,
                                        tenant=tenant_id)
        utils.juju_log('INFO', "Granted user '%s' role '%s' on tenant '%s'" % \
                       (user, role, tenant))
    else:
        utils.juju_log('INFO',
                       "User '%s' already has role '%s' on tenant '%s'" % \
                       (user, role, tenant))


def generate_admin_token(config):
    """ generate and add an admin token """
    import manager
    manager = manager.KeystoneManager(endpoint=get_local_endpoint(),
                                      token='ADMIN')
    if config["admin-token"] == "None":
        import random
        token = random.randrange(1000000000000, 9999999999999)
    else:
        return config["admin-token"]
    manager.api.add_token(token, config["admin-user"],
                          "admin", config["token-expiry"])
    utils.juju_log('INFO', "Generated and added new random admin token.")
    return token


def ensure_initial_admin(config):
    """ Ensures the minimum admin stuff exists in whatever database we're
        using.
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
        utils.juju_log('INFO', "Loading stored passwd from %s" % stored_passwd)
        passwd = open(stored_passwd, 'r').readline().strip('\n')
    if passwd == "":
        utils.juju_log('INFO', "Generating new passwd for user: %s" % \
                       config["admin-user"])
        passwd = execute("pwgen -c 16 1", die=True)[0]
        open(stored_passwd, 'w+').writelines("%s\n" % passwd)

    create_user(config['admin-user'], passwd, tenant='admin')
    update_user_password(config['admin-user'], passwd)
    create_role(config['admin-role'], config['admin-user'], 'admin')
    # TODO(adam_g): The following roles are likely not needed since redux merge
    create_role("KeystoneAdmin", config["admin-user"], 'admin')
    create_role("KeystoneServiceAdmin", config["admin-user"], 'admin')
    create_service_entry("keystone", "identity", "Keystone Identity Service")

    if cluster.is_clustered():
        utils.juju_log('INFO', "Creating endpoint for clustered configuration")
        service_host = auth_host = config["vip"]
    else:
        utils.juju_log('INFO', "Creating standard endpoint")
        service_host = auth_host = config["hostname"]

    for region in config['region'].split():
        create_keystone_endpoint(service_host=service_host,
                                 service_port=config["service-port"],
                                 auth_host=auth_host,
                                 auth_port=config["admin-port"],
                                 region=region)


def create_keystone_endpoint(service_host, service_port,
                             auth_host, auth_port, region):
    public_url = "http://%s:%s/v2.0" % (service_host, service_port)
    admin_url = "http://%s:%s/v2.0" % (auth_host, auth_port)
    internal_url = "http://%s:%s/v2.0" % (service_host, service_port)
    create_endpoint_template(region, "keystone", public_url,
                             admin_url, internal_url)


def update_user_password(username, password):
    import manager
    manager = manager.KeystoneManager(endpoint=get_local_endpoint(),
                                      token=get_admin_token())
    utils.juju_log('INFO', "Updating password for user '%s'" % username)

    user_id = manager.resolve_user_id(username)
    if user_id is None:
        error_out("Could not resolve user id for '%s'" % username)

    manager.api.users.update_password(user=user_id, password=password)
    utils.juju_log('INFO', "Successfully updated password for user '%s'" % \
                   username)


def load_stored_passwords(path=SERVICE_PASSWD_PATH):
    creds = {}
    if not os.path.isfile(path):
        return creds

    stored_passwd = open(path, 'r')
    for l in stored_passwd.readlines():
        user, passwd = l.strip().split(':')
        creds[user] = passwd
    return creds


def save_stored_passwords(path=SERVICE_PASSWD_PATH, **creds):
    with open(path, 'wb') as stored_passwd:
        [stored_passwd.write('%s:%s\n' % (u, p)) for u, p in creds.iteritems()]


def get_service_password(service_username):
    creds = load_stored_passwords()
    if service_username in creds:
        return creds[service_username]

    passwd = subprocess.check_output(['pwgen', '-c', '32', '1']).strip()
    creds[service_username] = passwd
    save_stored_passwords(**creds)

    return passwd


def configure_pki_tokens(config):
    '''Configure PKI token signing, if enabled.'''
    if config['enable-pki'] not in ['True', 'true']:
        update_config_block('signing', token_format='UUID')
    else:
        utils.juju_log('INFO', 'TODO: PKI Support, setting to UUID for now.')
        update_config_block('signing', token_format='UUID')


def do_openstack_upgrade(install_src, packages):
    '''Upgrade packages from a given install src.'''

    config = config_get()
    old_vers = get_os_codename_package('keystone')
    new_vers = get_os_codename_install_source(install_src)

    utils.juju_log('INFO',
                   "Beginning Keystone upgrade: %s -> %s" % \
                   (old_vers, new_vers))

    # Backup previous config.
    utils.juju_log('INFO', "Backing up contents of /etc/keystone.")
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
    ids = utils.relation_ids('shared-db')

    if ids:
        for rid in ids:
            for unit in utils.relation_list(rid):
                utils.juju_log('INFO',
                               'Configuring new keystone.conf for '
                               'database access on existing database'
                               ' relation to %s' % unit)
                relation_data = utils.relation_get_dict(relation_id=rid,
                                                        remote_unit=unit)

                update_config_block('sql', connection="mysql://%s:%s@%s/%s" %
                                        (config["database-user"],
                                         relation_data["password"],
                                         relation_data["private-address"],
                                         config["database"]))

    utils.stop('keystone')
    if (cluster.eligible_leader(CLUSTER_RES)):
        utils.juju_log('INFO',
                       'Running database migrations for %s' % new_vers)
        execute('keystone-manage db_sync', echo=True, die=True)
    else:
        utils.juju_log('INFO',
                       'Not cluster leader; snoozing whilst'
                       ' leader upgrades DB')
        time.sleep(10)
    utils.start('keystone')
    time.sleep(5)
    utils.juju_log('INFO',
                   'Completed Keystone upgrade: '
                   '%s -> %s' % (old_vers, new_vers))


def synchronize_service_credentials():
    '''
    Broadcast service credentials to peers or consume those that have been
    broadcasted by peer, depending on hook context.
    '''
    if (not cluster.eligible_leader(CLUSTER_RES) or
        not os.path.isfile(SERVICE_PASSWD_PATH)):
        return
    utils.juju_log('INFO', 'Synchronizing service passwords to all peers.')
    unison.sync_to_peers(peer_interface='cluster',
                         paths=[SERVICE_PASSWD_PATH], user=SSH_USER,
                         verbose=True)

CA = []


def get_ca(user='keystone', group='keystone'):
    """
    Initialize a new CA object if one hasn't already been loaded.
    This will create a new CA or load an existing one.
    """
    if not CA:
        if not os.path.isdir(SSL_DIR):
            os.mkdir(SSL_DIR)
        d_name = '_'.join(SSL_CA_NAME.lower().split(' '))
        ca = ssl.JujuCA(name=SSL_CA_NAME, user=user, group=group,
                        ca_dir=os.path.join(SSL_DIR,
                                            '%s_intermediate_ca' % d_name),
                        root_ca_dir=os.path.join(SSL_DIR,
                                            '%s_root_ca' % d_name))
        # SSL_DIR is synchronized via all peers over unison+ssh, need
        # to ensure permissions.
        execute('chown -R %s.%s %s' % (user, group, SSL_DIR))
        execute('chmod -R g+rwx %s' % SSL_DIR)
        CA.append(ca)
    return CA[0]


def https():
    if (utils.config_get('https-service-endpoints') in ["yes", "true", "True"]
        or cluster.https()):
        return True
    else:
        return False
