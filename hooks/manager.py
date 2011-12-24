#!/usr/bin/python
#
# Bootstraps the keystone API so we can utilize its managment API natively
import keystone.manage
import keystone.backends as db
from keystone import version
from keystone.common import config
from keystone.manage import api
from keystone.manage import RaisingOptionParser

parser = RaisingOptionParser("", version='%%prog %s'
         % version.version())
(options, args) = config.parse_options(parser)
_config_file, conf = config.load_paste_config('admin', options, args)
db.configure_backends(conf.global_conf)
