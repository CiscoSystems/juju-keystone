This charm provides Keystone, the Openstack identity service.  It's target
platform is Ubuntu Precise + Openstack Essex.  This has not been tested
using Oneiric + Diablo.

It provides two interfaces.
 
    - identity-service:  Openstack API endpoints request an entry in the 
      Keystone service catalog + endpoint template catalog.  When a relation
      is established, Keystone receives: service name, region, public_url,
      admin_url and internal_url.  It first checks that the requested service
      is listed as a supported service.  This list should stay updated to
      support current Openstack core services.  If the services is supported,
      a entry in the service catalog is created, an endpoint template is
      created and a admin token is generated.   The other end of the relation
      recieves the token as well as info on which ports Keystone is listening.

    - keystone-service:  This is currently only used by Horizon/dashboard
      as its interaction with Keystone is different from other Openstack API
      servicies.  That is, Horizon requests a Keystone role and token exists.
      During a relation, Horizon requests its configured default role and
      Keystone responds with a token and the auth + admin ports on which
      Keystone is listening.

Keystone requires a database.  By default, a local sqlite database is used.
The charm supports relations to a shared-db via mysql-shared interface.  When
a new data store is configured, the charm ensures the minimum administrator
credentials exist (as configured via charm configuration)

VIP is only required if you plan on multi-unit clusterming. The VIP becomes a highly-available API endpoint.
