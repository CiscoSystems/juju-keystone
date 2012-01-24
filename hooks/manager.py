#!/usr/bin/python
#
# Bootstraps the keystone API so we can utilize its managment API natively

import keystone.manage
import keystone.manage2
import keystone.backends as db
from keystone import version
from keystone.common import config
from keystone import config as new_config
from keystone.manage import api
from keystone.manage import RaisingOptionParser
import utils

parser = RaisingOptionParser("", version='%%prog %s'
         % version.version())
(options, args) = config.parse_options(parser)
_config_file, conf = config.load_paste_config('admin', options, args)

# get config location from juju charm config
config = utils.config_get()["config-file"]

CONF = new_config.CONF

CONF(config_files=[config])
db.configure_backends()
