#!/usr/bin/python

import time
import urlparse

from base64 import b64encode

from keystone_utils import (
    config_get,
    execute,
    update_config_block,
    set_admin_token,
    ensure_initial_admin,
    create_service_entry,
    create_endpoint_template,
    create_role,
    get_admin_token,
    get_service_password,
    create_user,
    grant_role,
    get_ca,
    synchronize_service_credentials,
    do_openstack_upgrade,
    configure_pki_tokens,
    SSH_USER,
    SSL_DIR,
    CLUSTER_RES,
    https
    )

from lib.openstack_common import (
    get_os_codename_install_source,
    get_os_codename_package,
    get_os_version_codename,
    get_os_version_package,
    save_script_rc
    )
import lib.unison as unison
import lib.utils as utils
import lib.cluster_utils as cluster
import lib.haproxy_utils as haproxy

config = config_get()

packages = [
    "keystone", "python-mysqldb", "pwgen",
    "haproxy", "python-jinja2", "openssl", "unison"
    ]
service = "keystone"

# used to verify joined services are valid openstack components.
# this should reflect the current "core" components of openstack
# and be expanded as we add support for them as a distro
valid_services = {
    "nova": {
        "type": "compute",
        "desc": "Nova Compute Service"
    },
    "nova-volume": {
        "type": "volume",
        "desc": "Nova Volume Service"
    },
    "cinder": {
        "type": "volume",
        "desc": "Cinder Volume Service"
    },
    "ec2": {
        "type": "ec2",
        "desc": "EC2 Compatibility Layer"
    },
    "glance": {
        "type": "image",
        "desc": "Glance Image Service"
    },
    "s3": {
        "type": "s3",
        "desc": "S3 Compatible object-store"
    },
    "swift": {
        "type": "object-store",
        "desc": "Swift Object Storage Service"
    },
    "quantum": {
        "type": "network",
        "desc": "Quantum Networking Service"
    },
    "oxygen": {
        "type": "oxygen",
        "desc": "Oxygen Cloud Image Service"
    },
    "ceilometer": {
        "type": "metering",
        "desc": "Ceilometer Metering Service"
    }
}


def install_hook():
    utils.configure_source()
    utils.install(*packages)
    update_config_block('DEFAULT',
                public_port=cluster.determine_api_port(config["service-port"]))
    update_config_block('DEFAULT',
                admin_port=cluster.determine_api_port(config["admin-port"]))
    set_admin_token(config['admin-token'])

    # set all backends to use sql+sqlite, if they are not already by default
    update_config_block('sql',
                        connection='sqlite:////var/lib/keystone/keystone.db')
    update_config_block('identity',
                        driver='keystone.identity.backends.sql.Identity')
    update_config_block('catalog',
                        driver='keystone.catalog.backends.sql.Catalog')
    update_config_block('token',
                        driver='keystone.token.backends.sql.Token')
    update_config_block('ec2',
                        driver='keystone.contrib.ec2.backends.sql.Ec2')

    utils.stop('keystone')
    execute("keystone-manage db_sync")
    utils.start('keystone')

    # ensure user + permissions for peer relations that
    # may be syncing data there via SSH_USER.
    unison.ensure_user(user=SSH_USER, group='keystone')
    execute("chmod -R g+wrx /var/lib/keystone/")

    time.sleep(5)
    ensure_initial_admin(config)


def db_joined():
    relation_data = {
        "database": config["database"],
        "username": config["database-user"],
        "hostname": config["hostname"]
        }
    utils.relation_set(**relation_data)


def db_changed():
    relation_data = utils.relation_get_dict()
    if ('password' not in relation_data or
        'db_host' not in relation_data):
        utils.juju_log('INFO',
                       "db_host or password not set. Peer not ready, exit 0")
        return

    update_config_block('sql', connection="mysql://%s:%s@%s/%s" %
                            (config["database-user"],
                             relation_data["password"],
                             relation_data["db_host"],
                             config["database"]))

    utils.stop('keystone')
    if cluster.eligible_leader(CLUSTER_RES):
        utils.juju_log('INFO',
                       'Cluster leader, performing db-sync')
        execute("keystone-manage db_sync", echo=True)
    utils.start('keystone')
    time.sleep(5)

    if cluster.eligible_leader(CLUSTER_RES):
        ensure_initial_admin(config)
        # If the backend database has been switched to something new and there
        # are existing identity-service relations,, service entries need to be
        # recreated in the new database.  Re-executing identity-service-changed
        # will do this.
        for rid in utils.relation_ids('identity-service'):
            for unit in utils.relation_list(rid=rid):
                utils.juju_log('INFO',
                               "Re-exec'ing identity-service-changed"
                               " for: %s - %s" % (rid, unit))
                identity_changed(relation_id=rid, remote_unit=unit)


def ensure_valid_service(service):
    if service not in valid_services.keys():
        utils.juju_log('WARNING',
                       "Invalid service requested: '%s'" % service)
        utils.relation_set(admin_token=-1)
        return


def add_endpoint(region, service, publicurl, adminurl, internalurl):
    desc = valid_services[service]["desc"]
    service_type = valid_services[service]["type"]
    create_service_entry(service, service_type, desc)
    create_endpoint_template(region=region, service=service,
                             publicurl=publicurl,
                             adminurl=adminurl,
                             internalurl=internalurl)


def identity_joined():
    """ Do nothing until we get information about requested service """
    pass


def identity_changed(relation_id=None, remote_unit=None):
    """ A service has advertised its API endpoints, create an entry in the
        service catalog.
        Optionally allow this hook to be re-fired for an existing
        relation+unit, for context see see db_changed().
    """
    if not cluster.eligible_leader(CLUSTER_RES):
        utils.juju_log('INFO',
                       'Deferring identity_changed() to service leader.')
        return

    settings = utils.relation_get_dict(relation_id=relation_id,
                                       remote_unit=remote_unit)

    # the minimum settings needed per endpoint
    single = set(['service', 'region', 'public_url', 'admin_url',
                  'internal_url'])
    if single.issubset(settings):
        # other end of relation advertised only one endpoint
        if 'None' in [v for k, v in settings.iteritems()]:
            # Some backend services advertise no endpoint but require a
            # hook execution to update auth strategy.
            relation_data = {}
            # Check if clustered and use vip + haproxy ports if so
            if cluster.is_clustered():
                relation_data["auth_host"] = config['vip']
                relation_data["service_host"] = config['vip']
            else:
                relation_data["auth_host"] = config['hostname']
                relation_data["service_host"] = config['hostname']
            relation_data["auth_port"] = config['admin-port']
            relation_data["service_port"] = config['service-port']
            if config['https-service-endpoints'] in ['True', 'true']:
                # Pass CA cert as client will need it to
                # verify https connections
                ca = get_ca(user=SSH_USER)
                ca_bundle = ca.get_ca_bundle()
                relation_data['https_keystone'] = 'True'
                relation_data['ca_cert'] = b64encode(ca_bundle)
            utils.relation_set(**relation_data)
            return

        ensure_valid_service(settings['service'])

        add_endpoint(region=settings['region'], service=settings['service'],
                     publicurl=settings['public_url'],
                     adminurl=settings['admin_url'],
                     internalurl=settings['internal_url'])
        service_username = settings['service']
        https_cn = urlparse.urlparse(settings['internal_url'])
        https_cn = https_cn.hostname
    else:
        # assemble multiple endpoints from relation data. service name
        # should be prepended to setting name, ie:
        #  realtion-set ec2_service=$foo ec2_region=$foo ec2_public_url=$foo
        #  relation-set nova_service=$foo nova_region=$foo nova_public_url=$foo
        # Results in a dict that looks like:
        # { 'ec2': {
        #       'service': $foo
        #       'region': $foo
        #       'public_url': $foo
        #   }
        #   'nova': {
        #       'service': $foo
        #       'region': $foo
        #       'public_url': $foo
        #   }
        # }
        endpoints = {}
        for k, v in settings.iteritems():
            ep = k.split('_')[0]
            x = '_'.join(k.split('_')[1:])
            if ep not in endpoints:
                endpoints[ep] = {}
            endpoints[ep][x] = v
        services = []
        https_cn = None
        for ep in endpoints:
            # weed out any unrelated relation stuff Juju might have added
            # by ensuring each possible endpiont has appropriate fields
            #  ['service', 'region', 'public_url', 'admin_url', 'internal_url']
            if single.issubset(endpoints[ep]):
                ep = endpoints[ep]
                ensure_valid_service(ep['service'])
                add_endpoint(region=ep['region'], service=ep['service'],
                             publicurl=ep['public_url'],
                             adminurl=ep['admin_url'],
                             internalurl=ep['internal_url'])
                services.append(ep['service'])
                if not https_cn:
                    https_cn = urlparse.urlparse(ep['internal_url'])
                    https_cn = https_cn.hostname
        service_username = '_'.join(services)

    if 'None' in [v for k, v in settings.iteritems()]:
        return

    if not service_username:
        return

    token = get_admin_token()
    utils.juju_log('INFO',
                   "Creating service credentials for '%s'" % service_username)

    service_password = get_service_password(service_username)
    create_user(service_username, service_password, config['service-tenant'])
    grant_role(service_username, config['admin-role'],
               config['service-tenant'])

    # Allow the remote service to request creation of any additional roles.
    # Currently used by Swift and Ceilometer.
    if 'requested_roles' in settings and settings['requested_roles'] != 'None':
        roles = settings['requested_roles'].split(',')
        utils.juju_log('INFO',
                       "Creating requested roles: %s" % roles)
        for role in roles:
            create_role(role, service_username, config['service-tenant'])
            grant_role(service_username, role, config['service-tenant'])

    # As of https://review.openstack.org/#change,4675, all nodes hosting
    # an endpoint(s) needs a service username and password assigned to
    # the service tenant and granted admin role.
    # note: config['service-tenant'] is created in utils.ensure_initial_admin()
    # we return a token, information about our API endpoints, and the generated
    # service credentials
    relation_data = {
        "admin_token": token,
        "service_host": config["hostname"],
        "service_port": config["service-port"],
        "auth_host": config["hostname"],
        "auth_port": config["admin-port"],
        "service_username": service_username,
        "service_password": service_password,
        "service_tenant": config['service-tenant'],
        "https_keystone": "False",
        "ssl_cert": "",
        "ssl_key": "",
        "ca_cert": ""
    }

    if relation_id:
        relation_data['rid'] = relation_id

    # Check if clustered and use vip + haproxy ports if so
    if cluster.is_clustered():
        relation_data["auth_host"] = config['vip']
        relation_data["service_host"] = config['vip']

    # generate or get a new cert/key for service if set to manage certs.
    if config['https-service-endpoints'] in ['True', 'true']:
        ca = get_ca(user=SSH_USER)
        cert, key = ca.get_cert_and_key(common_name=https_cn)
        ca_bundle = ca.get_ca_bundle()
        relation_data['ssl_cert'] = b64encode(cert)
        relation_data['ssl_key'] = b64encode(key)
        relation_data['ca_cert'] = b64encode(ca_bundle)
        relation_data['https_keystone'] = 'True'
        unison.sync_to_peers(peer_interface='cluster',
                             paths=[SSL_DIR], user=SSH_USER, verbose=True)
    utils.relation_set(**relation_data)
    synchronize_service_credentials()


def config_changed():
    unison.ensure_user(user=SSH_USER, group='keystone')
    execute("chmod -R g+wrx /var/lib/keystone/")

    # Determine whether or not we should do an upgrade, based on the
    # the version offered in keyston-release.
    available = get_os_codename_install_source(config['openstack-origin'])
    installed = get_os_codename_package('keystone')

    if (available and
        get_os_version_codename(available) > \
            get_os_version_codename(installed)):
        # TODO: fixup this call to work like utils.install()
        do_openstack_upgrade(config['openstack-origin'], ' '.join(packages))

    env_vars = {'OPENSTACK_SERVICE_KEYSTONE': 'keystone',
                'OPENSTACK_PORT_ADMIN': cluster.determine_api_port(
                    config['admin-port']),
                'OPENSTACK_PORT_PUBLIC': cluster.determine_api_port(
                    config['service-port'])}
    save_script_rc(**env_vars)

    set_admin_token(config['admin-token'])

    if cluster.eligible_leader(CLUSTER_RES):
        utils.juju_log('INFO',
                       'Cluster leader - ensuring endpoint configuration'
                       ' is up to date')
        ensure_initial_admin(config)

    update_config_block('logger_root', level=config['log-level'],
                        file='/etc/keystone/logging.conf')
    if get_os_version_package('keystone') >= '2013.1':
        # PKI introduced in Grizzly
        configure_pki_tokens(config)

    utils.restart('keystone')

    if cluster.eligible_leader(CLUSTER_RES):
        utils.juju_log('INFO',
                       'Firing identity_changed hook'
                       ' for all related services.')
        # HTTPS may have been set - so fire all identity relations
        # again
        for r_id in utils.relation_ids('identity-service'):
            for unit in utils.relation_list(r_id):
                identity_changed(relation_id=r_id,
                                 remote_unit=unit)


def upgrade_charm():
    cluster_changed()
    if cluster.eligible_leader(CLUSTER_RES):
        utils.juju_log('INFO',
                       'Cluster leader - ensuring endpoint configuration'
                       ' is up to date')
        ensure_initial_admin(config)


def cluster_joined():
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)
    update_config_block('DEFAULT',
        public_port=cluster.determine_api_port(config["service-port"]))
    update_config_block('DEFAULT',
        admin_port=cluster.determine_api_port(config["admin-port"]))
    utils.restart('keystone')
    service_ports = {
        "keystone_admin": [
            cluster.determine_haproxy_port(config['admin-port']),
            cluster.determine_api_port(config["admin-port"])
            ],
        "keystone_service": [
            cluster.determine_haproxy_port(config['service-port']),
            cluster.determine_api_port(config["service-port"])
            ]
        }
    haproxy.configure_haproxy(service_ports)


def cluster_changed():
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)
    synchronize_service_credentials()
    service_ports = {
        "keystone_admin": [
            cluster.determine_haproxy_port(config['admin-port']),
            cluster.determine_api_port(config["admin-port"])
            ],
        "keystone_service": [
            cluster.determine_haproxy_port(config['service-port']),
            cluster.determine_api_port(config["service-port"])
            ]
        }
    haproxy.configure_haproxy(service_ports)


def ha_relation_changed():
    relation_data = utils.relation_get_dict()
    if ('clustered' in relation_data and
        cluster.is_leader(CLUSTER_RES)):
        utils.juju_log('INFO',
                       'Cluster configured, notifying other services'
                       ' and updating keystone endpoint configuration')
        # Update keystone endpoint to point at VIP
        ensure_initial_admin(config)
        # Tell all related services to start using
        # the VIP and haproxy ports instead
        for r_id in utils.relation_ids('identity-service'):
            utils.relation_set(rid=r_id,
                               auth_host=config['vip'],
                               service_host=config['vip'])


def ha_relation_joined():
    # Obtain the config values necessary for the cluster config. These
    # include multicast port and interface to bind to.
    corosync_bindiface = config['ha-bindiface']
    corosync_mcastport = config['ha-mcastport']
    vip = config['vip']
    vip_cidr = config['vip_cidr']
    vip_iface = config['vip_iface']

    # Obtain resources
    resources = {
        'res_ks_vip': 'ocf:heartbeat:IPaddr2',
        'res_ks_haproxy': 'lsb:haproxy'
        }
    resource_params = {
        'res_ks_vip': 'params ip="%s" cidr_netmask="%s" nic="%s"' % \
                      (vip, vip_cidr, vip_iface),
        'res_ks_haproxy': 'op monitor interval="5s"'
        }
    init_services = {
        'res_ks_haproxy': 'haproxy'
        }
    clones = {
        'cl_ks_haproxy': 'res_ks_haproxy'
        }

    utils.relation_set(init_services=init_services,
                       corosync_bindiface=corosync_bindiface,
                       corosync_mcastport=corosync_mcastport,
                       resources=resources,
                       resource_params=resource_params,
                       clones=clones)


hooks = {
    "install": install_hook,
    "shared-db-relation-joined": db_joined,
    "shared-db-relation-changed": db_changed,
    "identity-service-relation-joined": identity_joined,
    "identity-service-relation-changed": identity_changed,
    "config-changed": config_changed,
    "cluster-relation-joined": cluster_joined,
    "cluster-relation-changed": cluster_changed,
    "cluster-relation-departed": cluster_changed,
    "ha-relation-joined": ha_relation_joined,
    "ha-relation-changed": ha_relation_changed,
    "upgrade-charm": upgrade_charm
}

utils.do_hooks(hooks)
