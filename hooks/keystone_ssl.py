#!/usr/bin/python

import base64
import os
import shutil
import subprocess
import tarfile
import tempfile
from utils import *

CA_EXPIRY = '365'
ORG_NAME = 'Ubuntu'
ORG_UNIT = 'Ubuntu Cloud'
CA_BUNDLE='/usr/local/share/ca-certificates/juju_ca_cert.crt'

CA_CONFIG = """
[ ca ]
default_ca = CA_default

[ CA_default ]
dir                     = %(ca_dir)s
policy                  = policy_match
database                = $dir/index.txt
serial                  = $dir/serial
certs                   = $dir/certs
crl_dir                 = $dir/crl
new_certs_dir           = $dir/newcerts
certificate             = $dir/cacert.pem
private_key             = $dir/private/cacert.key
RANDFILE                = $dir/private/.rand
default_md              = default

[ req ]
default_bits            = 1024
default_md              = sha1

prompt                  = no
distinguished_name      = ca_distinguished_name

x509_extensions         = ca_extensions

[ ca_distinguished_name ]
organizationName        = %(org_name)s
organizationalUnitName  = %(org_unit_name)s Certificate Authority
commonName              = %(common_name)s

[ policy_match ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied

[ ca_extensions ]
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer
keyUsage                = cRLSign, keyCertSign
"""

SIGNING_CONFIG="""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir                     = %(ca_dir)s
policy                  = policy_match
database                = $dir/index.txt
serial                  = $dir/serial
certs                   = $dir/certs
crl_dir                 = $dir/crl
new_certs_dir           = $dir/newcerts
certificate             = $dir/cacert.pem
private_key             = $dir/private/cacert.key
RANDFILE                = $dir/private/.rand
default_md              = default

[ req ]
default_bits            = 1024
default_md              = sha1

prompt                  = no
distinguished_name      = req_distinguished_name

x509_extensions         = req_extensions

[ req_distinguished_name ]
organizationName        = %(org_name)s
organizationalUnitName  = %(org_unit_name)s Server Farm

[ policy_match ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied

[ req_extensions ]
basicConstraints        = CA:false
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always, issuer
keyUsage                = digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage        = serverAuth, clientAuth
"""


def init_ca(ca_dir, common_name, org_name=ORG_NAME, org_unit_name=ORG_UNIT):
    print 'Ensuring certificate authority exists at %s.' % ca_dir
    if not os.path.exists(ca_dir):
        print 'Initializing new certificate authority at %s' % ca_dir
        os.mkdir(ca_dir)

    for i in ['certs', 'crl', 'newcerts', 'private']:
        d = os.path.join(ca_dir, i)
        if not os.path.exists(d):
            print 'Creating %s.' % d
            os.mkdir(d)
    os.chmod(os.path.join(ca_dir, 'private'), 0710)

    if not os.path.isfile(os.path.join(ca_dir, 'serial')):
        with open(os.path.join(ca_dir, 'serial'), 'wb') as out:
            out.write('01\n')

    if not os.path.isfile(os.path.join(ca_dir, 'index.txt')):
        with open(os.path.join(ca_dir, 'index.txt'), 'wb') as out:
            out.write('')
    if not os.path.isfile(os.path.join(ca_dir, 'ca.cnf')):
        print 'Creating new CA config in %s' % ca_dir
        with open(os.path.join(ca_dir, 'ca.cnf'), 'wb') as out:
            out.write(CA_CONFIG % locals())


def root_ca_crt_key(ca_dir):
    init = False
    crt = os.path.join(ca_dir, 'cacert.pem')
    key = os.path.join(ca_dir, 'private', 'cacert.key')
    for f in [crt, key]:
        if not os.path.isfile(f):
            print 'Missing %s, will re-initialize cert+key.' % f
            init = True
        else:
            print 'Found %s.' % f
    if init:
        cmd = ['openssl', 'req', '-config', os.path.join(ca_dir, 'ca.cnf'), '-x509',
               '-nodes', '-newkey', 'rsa', '-days', '21360', '-keyout', key,
               '-out', crt, '-outform', 'PEM']
        subprocess.check_call(cmd)
    return crt, key


def intermediate_ca_csr_key(ca_dir):
    print 'Creating new intermediate CSR.'
    key = os.path.join(ca_dir, 'private', 'cacert.key')
    csr = os.path.join(ca_dir, 'cacert.csr')
    cmd = ['openssl', 'req', '-config', os.path.join(ca_dir, 'ca.cnf'), '-sha1',
           '-newkey', 'rsa', '-nodes', '-keyout', key, '-out', csr, '-outform',
           'PEM']
    subprocess.check_call(cmd)
    return csr, key


def sign_int_csr(ca_dir, csr, common_name):
    print 'Signing certificate request %s.' % csr
    crt = os.path.join(ca_dir, 'certs',
                        '%s.crt' % os.path.basename(csr).split('.')[0])
    subj = '/O=%s/OU=%s/CN=%s' % (ORG_NAME, ORG_UNIT, common_name)
    cmd = ['openssl', 'ca', '-batch', '-config', os.path.join(ca_dir, 'ca.cnf'),
           '-extensions', 'ca_extensions', '-days', CA_EXPIRY, '-notext',
           '-in', csr, '-out', crt, '-subj', subj, '-batch']
    print ' '.join(cmd)
    subprocess.check_call(cmd)
    return crt


def init_root_ca(ca_dir, common_name):
    init_ca(ca_dir, common_name)
    return root_ca_crt_key(ca_dir)


def init_intermediate_ca(ca_dir, common_name, root_ca_dir,
                         org_name=ORG_NAME, org_unit_name=ORG_UNIT):
    init_ca(ca_dir, common_name)
    if not os.path.isfile(os.path.join(ca_dir, 'cacert.pem')):
        csr, key = intermediate_ca_csr_key(ca_dir)
        crt = sign_int_csr(root_ca_dir, csr, common_name)
        shutil.copy(crt, os.path.join(ca_dir, 'cacert.pem'))
    else:
        print 'Intermediate CA certificate already exists.'

    if not os.path.isfile(os.path.join(ca_dir, 'signing.cnf')):
        print 'Creating new signing config in %s' % ca_dir
        with open(os.path.join(ca_dir, 'signing.cnf'), 'wb') as out:
            out.write(SIGNING_CONFIG % locals())


def create_certificate(ca_dir, service):
    common_name = service
    subj = '/O=%s/OU=%s/CN=%s' % (ORG_NAME, ORG_UNIT, common_name)
    csr = os.path.join(ca_dir, 'certs', '%s.csr' % service)
    key = os.path.join(ca_dir, 'certs', '%s.key' % service)
    cmd = ['openssl', 'req', '-sha1', '-newkey', 'rsa', '-nodes', '-keyout',
           key, '-out', csr, '-subj', subj]
    subprocess.check_call(cmd)
    crt = sign_csr(ca_dir, csr, common_name)
    print 'Signed new CSR, crt @ %s' % crt
    return

def update_bundle(bundle_file, new_bundle):
    return
    if os.path.isfile(bundle_file):
        current = open(bundle_file, 'r').read().strip()
        if new_bundle == current:
            print 'CA Bundle @ %s is up to date.' % bundle_file
            return
        else:
            print 'Updating CA bundle @ %s.' % bundle_file

    with open(bundle_file, 'wb') as out:
        out.write(new_bundle)
    subprocess.check_call(['update-ca-certificates'])

def tar_directory(path):
    cwd = os.getcwd()
    parent=os.path.dirname(path)
    directory=os.path.basename(path)
    tmp = tempfile.TemporaryFile()
    os.chdir(parent)
    tarball = tarfile.TarFile(fileobj=tmp, mode='w')
    tarball.add(directory)
    tarball.close()
    tmp.seek(0)
    out = tmp.read()
    tmp.close()
    os.chdir(cwd)
    return out

class JujuCA(object):
    def __init__(self, name, ca_dir, root_ca_dir, user, group):
        root_crt, root_key = init_root_ca(root_ca_dir,
                                          '%s Certificate Authority' % name)
        init_intermediate_ca(ca_dir,
                             '%s Intermediate Certificate Authority' % name,
                             root_ca_dir)
        self.ca_dir = ca_dir
        self.root_ca_dir = root_ca_dir
        self.user = user
        self.group = group
        update_bundle(CA_BUNDLE, self.get_ca_bundle())

    def _sign_csr(self, csr, service, common_name):
        subj = '/O=%s/OU=%s/CN=%s' % (ORG_NAME, ORG_UNIT, common_name)
        crt = os.path.join(self.ca_dir, 'certs', '%s.crt' % common_name)
        cmd = ['openssl', 'ca', '-config',
               os.path.join(self.ca_dir, 'signing.cnf'), '-extensions',
               'req_extensions', '-days', '365', '-notext', '-in', csr,
               '-out', crt, '-batch', '-subj', subj]
        subprocess.check_call(cmd)
        return crt

    def _create_certificate(self, service, common_name):
        subj = '/O=%s/OU=%s/CN=%s' % (ORG_NAME, ORG_UNIT, common_name)
        csr = os.path.join(self.ca_dir, 'certs', '%s.csr' % service)
        key = os.path.join(self.ca_dir, 'certs', '%s.key' % service)
        cmd = ['openssl', 'req', '-sha1', '-newkey', 'rsa', '-nodes', '-keyout',
               key, '-out', csr, '-subj', subj]
        subprocess.check_call(cmd)
        crt = self._sign_csr(csr, service, common_name)
        for f in [csr, crt, key]:
            cmd = ['chown', '%s.%s' % (self.user, self.group), f]
            subprocess.check_call(cmd)
        print 'Signed new CSR, crt @ %s' % crt
        return crt, key

    def get_cert_and_key(self, common_name):
        print 'Getting certificate and key for %s.' % common_name
        key = os.path.join(self.ca_dir, 'certs', '%s.key' % common_name)
        crt = os.path.join(self.ca_dir, 'certs', '%s.crt' % common_name)
        if os.path.isfile(crt):
            print 'Found existing certificate for %s.' % common_name
            crt = open(crt, 'r').read()
            try:
                key = open(key, 'r').read()
            except:
                print 'Could not load ssl private key for %s from %s' %\
                     (common_name, key)
                exit(1)
            return crt, key
        crt, key = self._create_certificate(common_name, common_name)
        return open(crt, 'r').read(), open(key, 'r').read()

    def get_ca_bundle(self):
        int_cert = open(os.path.join(self.ca_dir, 'cacert.pem')).read()
        root_cert = open(os.path.join(self.root_ca_dir, 'cacert.pem')).read()
        # NOTE: ordering of certs in bundle matters!
        return int_cert + root_cert
