# htgettoken gets OIDC bearer tokens by interacting with Hashicorp vault
#
# Nonstandard python libraries required:
#  gssapi
#  paramiko
#  urllib3
#
# This source file is Copyright (c) 2020, FERMI NATIONAL
#   ACCELERATOR LABORATORY.  All rights reserved.
#
# For details of the Fermitools (BSD) license see COPYING
#
# Author: Dave Dykstra dwd@fnal.gov

from __future__ import print_function

prog = "htgettoken"
version = "2.0"

import os
import sys
import socket
import ssl
import string
import base64
import struct
import json
import re
import shlex
import tempfile
import subprocess
import signal
import time
import logging
import secrets
import gssapi
import paramiko
from optparse import OptionParser
import urllib3
import http.client

# get the default certificates paths for this platform
_paths = ssl.get_default_verify_paths()
_default_cafile = _paths.cafile or ''
if _default_cafile == '':
    # can happen if someone sets SSL_CERT_FILE=""
    # try first the RHEL default path
    _try_cafile = '/etc/pki/tls/cert.pem'
    if os.path.isfile(_try_cafile):
        _default_cafile = _try_cafile
    else:
        # debian can have this even without SSL_CERT_FILE="", try its default
        _try_cafile = '/etc/ssl/certs/ca-certificates.crt'
        if os.path.isfile(_try_cafile):
            _default_cafile = _try_cafile
# prefer grid-security default capath
_default_capath = "/etc/grid-security/certificates"
if _paths.capath and not os.path.isdir(_default_capath):
    _default_capath = _paths.capath

defaults = {
    "cafile": _default_cafile,
    "capath": _default_capath,
}

# these are global
options = None
showprogress = False
logfile = sys.stderr
vaultserver = None
vaulthostname = None
vault = None # default instance of the vaulthost class

# enable printing utf-8 without crashing
sys.stdout = open(1, 'w', encoding='utf-8', closefd=False)
sys.stderr = open(2, 'w', encoding='utf-8', closefd=False)


def log(*args, **kwargs):
    """Print to a log file.

    Based on https://stackoverflow.com/a/26286311.
    """
    print(" ".join(map(str,args)), file=logfile, **kwargs)


class HtgettokenHandler(logging.StreamHandler):
    """Custom logger handler for urllib3 to send output to our log function.
    """
    def __init__(self):
        logging.StreamHandler.__init__(self)
    def emit(self, record):
        log(self.format(record))

root_logger = logging.getLogger()
log_format = '%(name)s - %(levelname)s - %(message)s'
log_handler = HtgettokenHandler()
log_handler.setFormatter(logging.Formatter(log_format))
root_logger.addHandler(log_handler)


def logerr(*args, **kwargs):
    """Always print to stderr.
    """
    print(" ".join(map(str,args)), file=sys.stderr, **kwargs)


def usage(parser, msg):
    """Print usage and exit.
    """
    logerr(prog + ": " + msg + '\n')
    parser.print_help(sys.stderr)
    sys.exit(2)


def fatal(msg, code=1):
    """Exit with a fatal error.
    """
    if (options is None) or not options.quiet:
        if showprogress:
            log()
        logerr(prog + ": " + msg)
    sys.exit(code)


def expandexception(e):
    """Expand an exception to get maximum info.
    """
    typ = type(e).__name__
    msg = typ + ': ' + str(e)
    if typ == 'GSSError':
        msg = typ + ':'
        for arg in e.args:
            msg += ' ' + arg + '.'
    return msg


def efatal(msg, e, code=1):
    """Print exception type name and contents after fatal error message.
    """
    fatal(msg + ': ' + expandexception(e), code)


def elog(msg, e):
    """Log an exception after given message.
    """
    log(msg + ': ' + expandexception(e))


class vaulthost:
    """This is very similar to corresponding code in the HTCondor VaultCredmon.

    A host may be round-robin. This uses an HTTPSConnectionPool to continue
    to use the same IP address for multiple connections.  If there is a
    connection timeout the IP address that caused it is removed from
    consideration.
    """
    ips = []
    pool = None
    host = ""
    port = 0
    hostalias = None

    def __init__(self, parsedurl):
        self.host = parsedurl.host
        self.port = parsedurl.port
        if options.vaultcertname is None:
            self.hostalias = self.host
        else:
            self.hostalias = options.vaultcertname

    def close(self):
        if self.pool != None:
            self.pool.close()
            self.pool = None

    def getips(self):
        info = socket.getaddrinfo(self.host, 0, 0, 0, socket.IPPROTO_TCP)

        self.ips = []
        # Use only IPv4 addresses if there are any
        for tuple in info:
            if tuple[0] == socket.AF_INET:
                self.ips.append(tuple[4][0])
        if len(self.ips) == 0:
            # Otherwise use the IPv6 addresses
            for tuple in info:
                if tuple[0] == socket.AF_INET6:
                    self.ips.append(tuple[4][0])
        if len(self.ips) == 0:
            raise RuntimeError('no ip address found for', self.host)

    def newpool(self):
        if self.pool != None:
            self.pool.close()
        self.pool = urllib3.HTTPSConnectionPool(self.ips[0],
                            timeout=urllib3.util.Timeout(connect=2, read=10),
                            assert_hostname=self.hostalias, port=self.port,
                            ca_cert_dir=options.capath, ca_certs=options.cafile)

    def request(self, path, headers=None, params=None, data=None, ignore_400=False):
        if len(self.ips) == 0:
            self.getips()
            self.newpool()
        while len(self.ips) > 0:
            try:
                method = 'GET'
                if data != None:
                    method = 'POST'
                resp = self.pool.request(method, path, headers=headers, fields=params, body=data, retries=0)
            except urllib3.exceptions.MaxRetryError as e:
                if type(e.reason) != urllib3.exceptions.ConnectTimeoutError:
                    raise e
                if len(self.ips) == 1:
                    raise e
                if options.verbose:
                    log('Connection timeout on %s ip %s, trying %s' % (self.host, self.ips[0], self.ips[1]))
                del self.ips[0]
                self.newpool()
            else:
                if resp.status == 400 and ignore_400:
                    if options.debug:
                        log("ignoring 400 status")
                    return resp
                if resp.status != 200 and resp.status != 204:
                    errormsg = http.client.responses[resp.status] + ":"
                    try:
                        jsondata = json.loads(resp.data.decode())
                    except:
                        errormsg += ' ' + resp.data.decode()
                    else:
                        if 'errors' in jsondata:
                            for error in jsondata['errors']:
                                errormsg += ' ' + error.encode('ascii','ignore').decode('ascii')
                    raise urllib3.exceptions.HTTPError(errormsg)

                return resp


def checkRequiredOptions(parser):
    """Check required options.

    Function from

    http://stackoverflow.com/questions/4407539/python-how-to-make-an-option-to-be-required-in-optparse
    """
    missing_options = []
    for option in parser.option_list:
        if (re.search(r'\(required\)$', option.help) and
                eval('options.' + option.dest) is None):
            missing_options.extend(option._long_opts)
    if len(missing_options) > 0:
        usage(parser, "Missing required parameters: " + str(missing_options))


def parseargs(parser, argv):
    """Parse command-line arguments.

    This is a function because it has to be done after both times
    the options are processed.
    """
    global options
    (options, args) = parser.parse_args(argv)
    if len(args) != 0:
        usage(parser, "no non-option arguments expected")

    # This is done here because capath may be needed to retrieve
    #  the options file.
    if options.capath is None:
        options.capath = os.getenv('X509_CERT_DIR') or defaults['capath']


def getVaultToken(vaulttokensecs, response):
    """Either extract the vault token from an auth response or exchange
    it for another one if either the lease_duration is too long or it
    includes an sshregister policy.
    """
    if 'auth' not in response:
        fatal("no 'auth' in response from %s" % vaultserver)
    auth = response['auth']

    if 'client_token' not in auth:
        fatal("no 'client_token' in response from %s" % vaultserver)
    vaulttoken = auth['client_token']

    policies = None
    if 'policies' in auth:
        for policy in auth['policies']:
            if policy.startswith('sshregister'):
                policies = auth['policies']
                policies.remove(policy)
                break

    if 'lease_duration' in auth and int(auth['lease_duration']) <= vaulttokensecs \
            and policies is None:
        # don't need to exchange, already the correct duration or shorter
        return vaulttoken

    # do a vault token exchange
    path = '/v1/' + 'auth/token/create'
    url = vaultserver + path
    if options.debug:
        # normally do this quietly; don't want to advertise the exchange
        log("Reading from", url)
    headers = {'X-Vault-Token': vaulttoken}
    data = {
        'ttl': options.vaulttokenttl,
        'renewable': 'false',
    }
    if policies is not None:
        data['policies'] = policies

    try:
        resp = vault.request(path, headers=headers, data=json.dumps(data).encode())
    except Exception as e:
        efatal("getting vault token from %s failed" % url, e)
    body = resp.data.decode()
    if options.debug:
        log("##### Begin vault token response")
        log(body)
        log("##### End vault token response")
    try:
        response = json.loads(body)
    except Exception as e:
        efatal("decoding response from %s failed" % url, e)
    if 'auth' in response and 'client_token' in response['auth']:
        return response['auth']['client_token']
    fatal("no vault token in response from %s" % url)


def checkVaultMinsecs(vaulttoken, vaulttokenminsecs):
    """Check for a minimum number of seconds remaining in vault token

    Return True if there's enough time remaining, else False.
    """
    # Look up info about the vault token
    path = '/v1/' + 'auth/token/lookup-self'
    url = vaultserver + path
    if options.debug:
        log("Reading from", url)
    headers = {'X-Vault-Token': vaulttoken}
    try:
        resp = vault.request(path, headers=headers)
    except Exception as e:
        elog("Looking up vault token at %s failed" % url, e)
        return False
    body = resp.data.decode()
    if options.debug:
        log("##### Begin vault lookup-self response")
        log(body)
        log("##### End vault lookup-self response")
    try:
        response = json.loads(body)
    except Exception as e:
        efatal("decoding response from %s failed" % url, e)
    if 'data' not in response or 'ttl' not in response['data']:
        fatal("ttl missing from lookup-self response")

    ttl = response['data']['ttl']
    if options.verbose:
        log("  " + str(ttl) + " seconds remaining")
    if vaulttokenminsecs <= ttl:
        return True
    return False


def getBearerToken(vaulttoken, vaultpath, vaultoutpath):
    """Read a bearer token from vault using the given vaulttoken and vaultpath.
    If vaultoutpath is not None, write out the vaulttoken to that path after
    success getting a bearer token or if options.nobearertoken is true.
    Also exit the program if options.nobearertoken is true.
    """
    if (options.scopes is not None) or (options.audience is not None):
        vaultpath = vaultpath.replace('/creds/', '/sts/')
    if options.showbearerurl:
        print(vaultserver + '/v1/' + vaultpath)
        options.showbearerurl = False
    if options.nobearertoken:
        # no bearer token needed
        # if vault token was obtained, write it out before exiting
        if vaultoutpath != None:
            writeTokenSafely("vault", vaulttoken, vaultoutpath)
        sys.exit(0)
    if options.verbose:
        log("  at path " + vaultpath)
    elif showprogress:
        log("Attempting to get token from " + vaultserver + " ...", end='', flush=True)
    path = '/v1/' + vaultpath
    url = vaultserver + path
    params = {'minimum_seconds': options.minsecs}
    if options.scopes is not None:
        params['scopes'] = options.scopes
    if options.audience is not None:
        params['audiences'] = options.audience
    if options.debug:
        log("Reading from", url)
    headers = {'X-Vault-Token': vaulttoken}
    try:
        resp = vault.request(path, headers=headers, params=params)
    except Exception as e:
        if options.verbose:
            elog("Read token from %s failed" % url, e)
        elif showprogress:
            log(" failed")
        return None
    body = resp.data.decode()
    if options.debug:
        log("##### Begin vault get bearer token response")
        log(body)
        log("##### End vault get bearer token response")
    try:
        response = json.loads(body)
    except Exception as e:
        efatal("decoding response from %s failed" % url, e)
    if 'data' in response and 'access_token' in response['data']:
        if showprogress:
            log(" succeeded")
        bearertoken = response['data']['access_token']
        if vaultoutpath != None:
            writeTokenSafely("vault", vaulttoken, vaultoutpath)
        return bearertoken
    if showprogress:
        log(" failed")
    return None

def isDevFile(file):
    return file.startswith("/dev/std") or file.startswith("/dev/fd")


def writeTokenSafely(tokentype, token, outfile):
    """Safely write out a token to where it might be a world-writable
    directory, unless the output is a device file
    """
    dorename = False
    if isDevFile(outfile):
        if options.debug:
            log("Writing", tokentype, "token to", outfile)
        try:
            handle = open(outfile, 'w')
        except Exception as e:
            efatal("failure opening for write", e)
    else:
        if options.verbose or showprogress:
            log("Storing", tokentype, "token in", outfile)
        # Attempt to remove the file first in case it exists, because os.O_EXCL
        #  requires it to be gone.  Need to use os.O_EXCL to prevent somebody
        #  else from pre-creating the file in order to steal credentials.
        try:
            os.remove(outfile)
        except:
            pass
        try:
            dir=os.path.dirname(outfile)
            if dir == '':
                dir = '.'
            fd, path = tempfile.mkstemp(prefix='.' + prog, dir=dir)
            handle = os.fdopen(fd, 'w')
        except Exception as e:
            efatal("failure creating file", e)
        dorename = True

    try:
        handle.write(token + '\n')
    except Exception as e:
        efatal("failure writing file", e)
    handle.close()

    if dorename:
        try:
            os.rename(path, outfile)
        except Exception as e:
            try:
                os.remove(outfile)
            except:
                pass
            efatal("failure renaming " + path + " to " + outfile, e)


def ttl2secs(ttl, msg):
    """Convert a time to live with trailing unit character into seconds.
    """
    # calculate ttl in seconds
    lastchr = ttl[-1:]
    numpart = ttl[0:-1]
    failmsg = msg + " is not a number followed by s, m, h, or d"
    if not numpart.isnumeric():
        fatal(failmsg)
    secs = int(numpart)
    if lastchr == 'd':
        secs *= 24
        lastchr = 'h'
    if lastchr == 'h':
        secs *= 60*60
    elif lastchr == 'm':
        secs *= 60
    elif lastchr != 's':
        fatal(failmsg)
    return secs


### htgettoken main ####
def main():
    global options
    usagestr = "usage: %prog [-h] [otheroptions]"
    parser = OptionParser(usage=usagestr, version=version, prog=prog)

    parser.add_option("-v", "--verbose",
                      action="store_true", default=False,
                      help="show detailed progress")
    parser.add_option("-d", "--debug",
                      action="store_true", default=False,
                      help="show debug output (implies -v)")
    parser.add_option("-q", "--quiet",
                      action="store_true", default=False,
                      help="do not print progress or error messages")
    parser.add_option("-s", "--optserver",
                      metavar="HostOrURL",
                      help="server or URL with default %s options" % prog)
    parser.add_option("-a", "--vaultserver",
                      metavar="HostOrURL",
                      help="vault server or URL (required)")
    parser.add_option("--vaultalias",
                      metavar="HostOrURL",
                      help="vault alias service name or URL [default same as vaultserver]")
    parser.add_option("--vaultcertname",
                      metavar="Host",
                      help="host certificate name to expect for vault server [default host name part of vaultserver]")
    parser.add_option("-i", "--issuer",
                      metavar="issuername",
                      default="default",
                      help="vault name of oidc token issuer")
    parser.add_option("-r", "--role",
                      metavar="rolename",
                      default="default",
                      help="vault name of role for oidc")
    parser.add_option("--nokerberos",
                      action="store_true", default=False,
                      help="skip attempting to use kerberos authentication")
    parser.add_option("--kerbpath",
                      metavar="vaultpath",
                      default="auth/kerberos-%issuer_%role",
                      help="path in vault for accessing kerberos authentication")
    parser.add_option("--kerbprincipal",
                      metavar="principal",
                      help="alternate kerberos principal for kerberos authentication")
    parser.add_option("--nooidc",
                      action="store_true", default=False,
                      help="skip attempting to use oidc authentication")
    parser.add_option("--oidcpath",
                      metavar="vaultpath",
                      default="auth/oidc-%issuer/oidc",
                      help="path in vault for accessing oidc authentication")
    parser.add_option("--nossh",
                      action="store_true", default=False,
                      help="skip attempting to use ssh-agent authentication")
    parser.add_option("--sshpath",
                      metavar="vaultpath",
                      default="auth/ssh",
                      help="path in vault for accessing ssh-agent authentication")
    parser.add_option("--registerssh",
                      action="store_true", default=False,
                      help="register ssh-agent keys (forces oidc authentication)")
    parser.add_option("-c", "--configdir",
                      metavar="path",
                      default="~/.config/" + prog,
                      help="path to directory to save configuration info")
    parser.add_option("--credkey",
                      metavar="key",
                      help="key to use in secretpath [default read from oidc and stored in %configdir/credkey-%issuer-%role]")
    parser.add_option("--secretpath",
                      metavar="vaultpath",
                      default = "secret/oauth/creds/%issuer/%credkey:%role",
                      help="path in vault for accessing the bearer token secret")
    parser.add_option("--vaulttokenttl",
                      metavar="time",
                      default="7d",
                      help="time (s, m, h, or d suffix) for new vault token to live")
    parser.add_option("--vaulttokenminttl",
                      metavar="time",
                      default="0s",
                      help="minimum time (s, m, h or d suffix) left in existing vault token before expiration")
    parser.add_option("--vaulttokenfile",
                      metavar="path",
                      help="path to save vault token [default /tmp/vt_u%uid if vaulttokenttl less than 1 million seconds, else /dev/stdout]")
    parser.add_option("--vaulttokeninfile",
                      metavar="path",
                      default="%vaulttokenfile",
                      help="path to read vault token from")
    parser.add_option("--showbearerurl",
                      action="store_true", default=False,
                      help="print the bearer URL to stdout")
    parser.add_option("--nobearertoken",
                      action="store_true", default=False,
                      help="skip getting a bearer token, always getting only a vault token")
    parser.add_option("-o", "--outfile",
                      metavar="path",
                      help="path to save bearer token " +
                        "[default: $BEARER_TOKEN_FILE or $XDG_RUNTIME_DIR/bt_u%uid]")
    parser.add_option("--minsecs",
                      type="int", metavar="seconds", default=60,
                      help="minimum number of seconds left in bearer token before expiration")
    parser.add_option("--scopes",
                      metavar="scopes",
                      help="reduced list of scopes for token")
    parser.add_option("--audience",
                      metavar="audience",
                      help="more restricted list of audiences for token")
    parser.add_option("--cafile",
                      metavar="file", default=defaults['cafile'],
                      help="Certifying Authority certificates bundle file")
    parser.add_option("--capath",
                      metavar="path",
                      help="Certifying Authority certificates directory " +
                      '[default: $X509_CERT_DIR or ' +
                      defaults['capath'] + ']')
    parser.add_option("--web-open-command",
                      metavar="command",
                      help="Command to execute to open a URL in a web browser " +
                      '[default: "xdg-open" unless $SSH_CLIENT is set]')

    # Change the default handler for SIGINT from raising a KeyboardInterrupt
    #  (which is ignored by urllib) to SIG_DFL (which exits)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # add default value (if any) to the help messages that are strings
    for option in parser.option_list:
        if (option.default != ("NO", "DEFAULT")) and (option.action == "store"):
            option.help += " [default: %default]"

    # look for default options in the environment
    envopts = os.getenv("HTGETTOKENOPTS", "")
    envargs = shlex.split(envopts, True)

    parseargs(parser, envargs + sys.argv[1:])

    if options.optserver is not None:
        # read additional options from optserver
        optserver = options.optserver
        if '://' not in optserver:
            optserver = 'https://' + optserver + '/' + prog + 'opts.txt'
        if options.verbose or options.debug:
            # Note that log messages here will always go to stderr 
            #  because it is too early to easily know if the options
            #  using stdout have been set
            log("Fetching options from " + optserver)
        optparsed = urllib3.util.parse_url(optserver)
        opthost = vaulthost(optparsed)
        try:
            resp = opthost.request(optparsed.path)
        except Exception as e:
            efatal("fetch of options from %s failed" % optserver, e)
        opts = resp.data.decode()
        opthost.close()
        if options.debug:
            log("##### Begin additional options")
            log(opts)
            log("##### End additional options")
        try:
            serverargs = shlex.split(opts, True)
        except Exception as e:
            efatal("parsing options from %s failed" % optserver, e)

        parseargs(parser, serverargs + envargs + sys.argv[1:])

    checkRequiredOptions(parser)

    # set implied options
    if options.debug:
        options.verbose = True
    global showprogress
    if not options.quiet and not options.verbose:
        showprogress = True
    if options.registerssh:
        options.nokerberos = True
        options.nossh = True

    # calculate vault token ttl and minttl in seconds
    vaulttokensecs = ttl2secs(options.vaulttokenttl, "--vaulttokenttl")
    # vault doesn't support the 'd' suffix to 'ttl' so always set it in seconds
    options.vaulttokenttl = str(vaulttokensecs) + 's'

    vaulttokenminsecs = 0
    if options.vaulttokenminttl is not None:
        vaulttokenminsecs = ttl2secs(options.vaulttokenminttl, "--vaulttokenminttl")
        if vaulttokenminsecs >= vaulttokensecs:
            fatal("--vaulttokenminttl must be less than --vaulttokenttl")

    # calculate defaults for options that are too complex for "default" keyword
    if options.outfile is None:
        options.outfile = os.getenv("BEARER_TOKEN_FILE")
        if options.outfile is None:
            tmpdir = os.getenv("XDG_RUNTIME_DIR")
            if tmpdir is None:
                tmpdir = '/tmp'
            options.outfile = tmpdir + "/bt_u%uid"
    outfile = options.outfile.replace("%uid", str(os.geteuid()))

    if options.vaulttokenfile is None:
        if vaulttokensecs > 1000000:
            options.vaulttokenfile = "/dev/stdout"
        else:
            options.vaulttokenfile = "/tmp/vt_u%uid"
    if vaulttokensecs > 1000000 and not isDevFile(options.vaulttokenfile):
        fatal("--vaulttokenfile must be under /dev/ when --vaulttokenttl is greater than a million seconds")

    if options.vaulttokenfile != "/dev/stdout" and not options.showbearerurl:
        # switch log output to stdout if nothing else is using it
        global logfile
        logfile=sys.stdout
        if options.debug:
            log("Enabling HTTPConnection debugging")
            # Unfortunately in urllib3 this only ever prints to stdout,
            # so only enable the HTTPConnection debugging when not needing
            # to parse stdout
            http.client.HTTPConnection.debuglevel = 5

    if not options.nooidc and not sys.stdout.isatty() \
                and not sys.stderr.isatty() and not sys.stdin.isatty():
        if options.verbose:
            log("Disabling oidc because running in the background")
        options.nooidc = True

    if options.web_open_command is None:
        sshclient = os.getenv("SSH_CLIENT")
        if sshclient is None:
            if sys.platform == 'darwin':
                options.web_open_command = 'open'
            else:
                options.web_open_command = 'xdg-open'
        else:
            options.web_open_command = ""

    # Get and parse the vaultserver URL
    global vaultserver
    vaultserver = options.vaultserver
    if '://' not in vaultserver:
        vaultserver = 'https://' + vaultserver
    vaultserverparts = vaultserver.split('/')
    if ':' not in vaultserverparts[2]:
        vaultserver = vaultserver + ':8200'
    vaultserverparsed = urllib3.util.parse_url(vaultserver)

    vaultalias = vaultserver
    vaultaliasparsed = vaultserverparsed
    if options.vaultalias is not None:
        # Similarly parse the vaultalias option
        # This is used when there are multiple servers implementing the
        #   same vault service, and the vaultserver option selects a
        #   specific one.
        vaultalias = options.vaultalias
        if '://' not in vaultalias:
            vaultalias = 'https://' + vaultalias
        vaultaliasparts = vaultalias.split('/')
        if ':' not in vaultaliasparts[2]:
            vaultalias = vaultalias + ':8200'
        vaultaliasparsed = urllib3.util.parse_url(vaultalias)

    global vaulthostname
    vaulthostname = vaultaliasparsed.host

    global vault
    vault = vaulthost(vaultserverparsed)

    secretpath = options.secretpath.replace("%issuer", options.issuer)
    secretpath = secretpath.replace("%role", options.role)
    vaulttokenfile = options.vaulttokenfile.replace("%uid", str(os.geteuid()))
    vaulttokenfile = os.path.expanduser(vaulttokenfile)
    vaulttokeninfile = options.vaulttokeninfile.replace("%vaulttokenfile", options.vaulttokenfile)
    vaulttokeninfile = vaulttokeninfile.replace("%uid", str(os.geteuid()))
    vaulttokeninfile = os.path.expanduser(vaulttokeninfile)
    vaulttoken = None
    bearertoken = None

    credkey = options.credkey
    configfile = None
    if credkey is None and (not options.nobearertoken or options.showbearerurl or not options.nossh):
        # Look for saved credkey, needed for figuring out the vault secretpath
        configfile = options.configdir + '/credkey-' + options.issuer + '-' + options.role
        configfile = os.path.expanduser(configfile)
        if not os.path.exists(configfile):
            if options.debug:
                log(configfile, "does not yet exist")
        else:
            if options.debug:
                log("Reading", configfile)
            try:
                with open(configfile, 'r') as file:
                    credkey = file.read().strip()
            except Exception as e:
                if options.debug:
                    elog("Could not read " + configfile, e)
            else:
                if options.verbose:
                    log("Credkey from %s: %s" % (configfile, credkey))

    if (credkey is not None or options.nobearertoken) and not options.registerssh:
        fullsecretpath = ""
        if credkey is None:
            if options.showbearerurl:
                fatal("cannot do --showbearerurl because credkey is not known")
        else:
            fullsecretpath = secretpath.replace("%credkey", credkey)

        # Check to see if a valid vault token already exists and works by
        #   attempting to read a bearer token
        if not os.path.exists(vaulttokeninfile):
            if options.debug:
                log(vaulttokeninfile, "does not yet exist")
        else:
            if options.debug:
                log("Reading", vaulttokeninfile)
            try:
                with open(vaulttokeninfile, 'r') as file:
                    vaulttoken = file.read().strip()
            except Exception as e:
                if options.debug:
                    elog("Could not load " + vaulttokeninfile, e)
            else:
                tryget = True
                if isDevFile(options.vaulttokeninfile):
                    # The incoming vault token location is coming from /dev,
                    #  so first try to exchange it for one with a duration
                    #  no longer than the requested duration and write that
                    #  out.  This is used to make a vault token with a
                    #  short enough lifetime to limit security risk when
                    #  stored on disk.

                    # construct fake "response" for getVaultToken
                    response = {'auth' : {'client_token': vaulttoken}}
                    vaulttoken = getVaultToken(vaulttokensecs, response)
                    writeTokenSafely("vault", vaulttoken, vaulttokenfile)
                elif options.nobearertoken:
                    # force getting a new vault token
                    tryget = False
                elif vaulttokenminsecs > 0:
                    if options.verbose:
                        log("Making sure there is at least " + str(vaulttokenminsecs) + " seconds remaining")
                        log("  in vault token from", vaulttokeninfile)

                    tryget = checkVaultMinsecs(vaulttoken, vaulttokenminsecs)
            
                if tryget:
                    if options.verbose and not options.nobearertoken:
                        log("Attempting to get bearer token from", vaultserver)
                        log("  using vault token from", vaulttokeninfile)

                    bearertoken = getBearerToken(vaulttoken, fullsecretpath, None)
            
        if bearertoken is None and not options.nokerberos:
            # Try kerberos authentication with vault
            service = "host@" + vaulthostname
            if options.verbose:
                log("Initializing kerberos client for", service)
            elif showprogress:
                log("Attempting kerberos auth with " + vaultserver + " ...", end='', flush=True)

            # Need to disable kerberos reverse DNS lookup in order to
            #  work properly with server aliases
            cfgfile = tempfile.NamedTemporaryFile(mode='w')
            if options.debug:
                log("Disabling kerberos reverse DNS lookup in " + cfgfile.name) 
            cfgfile.write("[libdefaults]\n    rdns = false\n")
            cfgfile.flush()

            krb5_config = os.getenv("KRB5_CONFIG")
            if krb5_config is None:
                # Try not reading from /etc/krb5.conf because it can
                # interfere if the kerberos domain is missing
                os.environ["KRB5_CONFIG"] = cfgfile.name
            else:
                os.environ["KRB5_CONFIG"] = cfgfile.name + ':' + krb5_config
            if options.debug:
                log("Setting KRB5_CONFIG=" + os.getenv("KRB5_CONFIG"))
            kname = gssapi.Name(base=service, name_type=gssapi.NameType.hostbased_service)
            kcontext = gssapi.SecurityContext(usage="initiate", name=kname)
            kresponse = None
            try:
                kresponse = kcontext.step()
            except Exception as e:
                if krb5_config is None and (len(e.args) != 2 or \
                        len(e.args[1]) != 2 or 'expired' not in e.args[1][0]):
                    # Try again with the default KRB5_CONFIG because 
                    # krb5.conf might be there and might work better.
                    # Don't do it for expired tickets because those have
                    # been observed to not always get caught with 2nd try.
                    if options.debug:
                        elog("Kerberos init without /etc/krb5.conf failed", e)
                        log("Trying again with /etc/krb5.conf")
                    os.environ["KRB5_CONFIG"] = cfgfile.name + ":/etc/krb5.conf"
                    if options.debug:
                        log("Setting KRB5_CONFIG=" + os.getenv("KRB5_CONFIG"))
                    kcontext = gssapi.SecurityContext(usage="initiate", name=kname)
                    try:
                        kresponse = kcontext.step()
                    except Exception as e2:
                        kresponse = None
                        e = e2
                if kresponse is None:
                    if options.verbose:
                        elog("Kerberos init failed", e)
                    elif showprogress:
                        log(" failed")

            cfgfile.close()

            if kresponse != None:
                kerberostoken = base64.b64encode(kresponse).decode()
                if options.debug:
                    log("Kerberos token:", kerberostoken)

                kerbpath = options.kerbpath.replace("%issuer", options.issuer)
                kerbpath = kerbpath.replace("%role", options.role)
                path = "/v1/" + kerbpath + '/login'
                url = vaultserver + path
                if options.verbose:
                    log("Negotiating kerberos with", vaultserver)
                    log("  at path " + kerbpath)
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Negotiate ' + kerberostoken
                }
                data = ''.encode('ascii')  # empty data is to force a POST
                try:
                    resp = vault.request(path, headers=headers, data=data)
                except Exception as e:
                    if showprogress:
                        log(" failed")
                    efatal("Kerberos negotiate with %s failed" % url, e)

                body = resp.data.decode()
                if options.debug:
                    log("##### Begin vault kerberos response")
                    log(body)
                    log("##### End vault kerberos response")
                response = json.loads(body)
                if 'auth' in response and response['auth'] is not None:
                    if showprogress:
                        log(" succeeded")
                    vaulttoken = getVaultToken(vaulttokensecs, response)
                    if options.verbose and not options.nobearertoken:
                        log("Attempting to get bearer token from " + vaultserver)

                    bearertoken = getBearerToken(vaulttoken, fullsecretpath, vaulttokenfile)

                elif options.verbose:
                    log("Kerberos authentication failed")
                    if options.debug:
                        if 'warnings' in response:
                            for warning in response['warnings']:
                                log("  " + warning)
                        if 'errors' in response:
                            for error in response['errors']:
                                log("  " + error)
                elif showprogress:
                    log(" failed")

        if bearertoken is None and not options.nossh:
            # Try ssh-agent authentication with vault
            vaulttoken = None
            try:
                agent = paramiko.Agent()
            except Exception as e:
                efatal("Error checking for ssh-agent keys", e)
            agent_keys = agent.get_keys()
            if len(agent_keys) == 0:
                if options.verbose:
                    log("No ssh-agent keys found")
            else:
                if showprogress:
                    log("Attempting ssh-agent auth with " + vaultserver + " ...", end='', flush=True)

                metadata = {
                    "issuer": options.issuer,
                    "group": options.role
                }

                keynum = 0
                for key in agent_keys:
                    keynum += 1
                    keyname = 'key' + str(keynum)

                    path = '/v1/' + options.sshpath + '/nonce'
                    url = vaultserver + path
                    if options.verbose:
                        log("Getting ssh nonce from " + url)
                    try:
                        resp = vault.request(path)
                    except Exception as e:
                        if options.verbose:
                            elog("Getting ssh nonce failed", e)
                        break
                    body = resp.data.decode()
                    if options.debug:
                        log("##### Begin ssh-agent nonce response")
                        log(body)
                        log("##### End ssh-agent nonce response")
                    data = json.loads(body)
                    nonce = data["data"]["nonce"]
                    b64nonce = base64.b64encode(nonce.encode()).decode()

                    d = key.sign_ssh_data(nonce)
                    parts = []
                    while d:
                        ln = struct.unpack('>I', d[:4])[0]
                        bits = d[4:ln+4]
                        parts.append(bits)
                        d = d[ln+4:]
                    sig = parts[1]
                    b64sig = base64.b64encode(sig).decode()

                    pubkey = key.get_name() + ' ' + key.get_base64() + ' ' + keyname
                    data = {
                        'role': credkey,
                        'public_key': pubkey,
                        'signature': b64sig,
                        'nonce': b64nonce,
                        'metadata': metadata
                    }
                    if metadata != {}:
                        data['metadata'] = metadata
                    datastr = json.dumps(data)

                    path = '/v1/' + options.sshpath + '/login'
                    url = vaultserver + path
                    if options.verbose:
                        log("Attempting to login with ssh " + keyname + " at " + url)
                    try:
                        resp = vault.request(path, data=datastr.encode())
                    except Exception as e:
                        if options.verbose:
                            elog("Logging in with ssh " + keyname + " failed", e)
                        continue

                    body = resp.data.decode()
                    if options.debug:
                        log("##### Begin ssh-agent login response")
                        log(body)
                        log("##### End ssh-agent login response")

                    try:
                        response = json.loads(body)
                    except Exception as e:
                        efatal("decoding response from %s failed" % vaultserver, e)

                    if 'auth' in response and response['auth'] is not None:
                        if showprogress:
                            log(" succeeded")
                        vaulttoken = getVaultToken(vaulttokensecs, response)
                        if options.verbose and not options.nobearertoken:
                            log("Attempting to get bearer token from " + vaultserver)

                        bearertoken = getBearerToken(vaulttoken, fullsecretpath, vaulttokenfile)

                    elif options.verbose:
                        log("ssh-agent authentication failed")
                        if options.debug:
                            if 'warnings' in response:
                                for warning in response['warnings']:
                                    log("  " + warning)
                            if 'errors' in response:
                                for error in response['errors']:
                                    log("  " + error)

                    break

                if showprogress and vaulttoken is None:
                    log(" failed")

    if bearertoken is None and not options.nooidc:
        if options.verbose or showprogress:
            log("Attempting OIDC authentication with", vaultserver)
        oidcpath = options.oidcpath.replace("%issuer", options.issuer)
        path = '/v1/' + oidcpath + '/auth_url'
        url = vaultserver + path
        nonce = secrets.token_urlsafe()
        authdata = {
            'role': options.role,
            'client_nonce': nonce,
            'redirect_uri': vaultalias + '/v1/' + oidcpath + '/callback'
        }
        data = json.dumps(authdata)
        if options.debug:
            log("Authenticating to", url)
            log("##### Begin authentication data")
            log(data)
            log("##### End authentication data")
        try:
            resp = vault.request(path, data=data.encode())
        except Exception as e:
            efatal("Initiating authentication to %s failed" % vaultserver, e)
        body = resp.data.decode()
        if options.debug:
            log("##### Begin vault initiate auth response")
            log(body)
            log("##### End vault initiate auth response")
        try:
            response = json.loads(body)
        except Exception as e:
            efatal("decoding response from %s failed" % vaultserver, e)

        if 'data' not in response:
            fatal("no 'data' in response from %s" % vaultserver)
        data = response['data']
        if 'auth_url' not in data:
            fatal("no 'auth_url' in data from %s" % vaultserver)
        auth_url = data['auth_url']
        del data['auth_url'] 
        if auth_url == "":
            fatal("'auth_url' is empty in data from %s" % vaultserver)

        log()
        log("Complete the authentication at:")
        log("    " + auth_url)
        if 'user_code' in data:
            log("When prompted, enter code " + data['user_code'])
            del data['user_code']
         
        opencmd = options.web_open_command
        if opencmd == "":
            log("No web open command defined, please copy/paste the above to any web browser")
        else:
            # Don't use python's webbrowser library; it tries too many things
            browser = os.getenv("BROWSER")
            if browser is None:
                # Avoid the default command-line browsers in xdg-open,
                #   especially lynx which hangs
                if os.getenv("DISPLAY") is None:
                    browser = "no-browser"
                else:
                    # list of common gui browsers copied from el7 xdg-open
                    browser = "x-www-browser:firefox:seamonkey:mozilla:epiphany:konqueror:chromium-browser:google-chrome"
                if options.debug:
                    log("Setting BROWSER=" + browser)
                os.putenv("BROWSER", browser)
            cp = None
            try:
                if not options.quiet:
                    log("Running '%s' on the URL" % opencmd)
                cp = subprocess.run([opencmd, auth_url], stderr=subprocess.DEVNULL)
            except:
                pass
            if cp is None or cp.returncode != 0:
                log("Couldn't open web browser with '%s', please open URL manually" % opencmd)

        if not options.quiet:
            log("Waiting for response in web browser")
        pollinterval = 0
        data['client_nonce'] = nonce
        datastr = ''
        if 'state' in data:
            path = '/v1/' + oidcpath + '/poll'
            if 'poll_interval' in data:
                pollinterval = int(data['poll_interval'])
                del data['poll_interval']
        else:
            # backward compatibility for old device flow implementation
            path = '/v1/' + oidcpath + '/device_wait'
            data['role'] = options.role
        url = vaultserver + path
        datastr = json.dumps(data)
        if options.debug:
            log("Continuing authentication at", url)
            if datastr != '':
                log("##### Begin continuation data")
                log(datastr)
                log("##### End continuation data")

        response = None
        secswaited = 0
        while True:
            try:
                if secswaited > 120:
                    fatal("Polling for response took longer than 2 minutes")
                if options.debug:
                    log("waiting for " + str(pollinterval) + " seconds")
                time.sleep(pollinterval)
                secswaited += pollinterval
                if options.debug:
                    log("polling")
                # The normal "authorized_pending" response comes in
                #  the body of a 400 Bad Request.  If we let the
                #  exception go as normal, the resp is not set and we
                #  can't read the body, so temporarily block 400 from
                #  throwing an exception.
                resp = vault.request(path, data=datastr.encode(), ignore_400=True)
            except Exception as e:
                efatal("Authentication to %s failed" % vaultserver, e)
            body = resp.data.decode()
            if options.debug:
                log("##### Begin vault auth response")
                log(body)
                log("##### End vault auth response")
            try:
                response = json.loads(body)
            except Exception as e:
                efatal("decoding response from %s failed" % vaultserver, e)
            if 'errors' in response:
                errors = response['errors']
                if errors[0] == "slow_down":
                    pollinterval = pollinterval * 2
                elif errors[0] != "authorization_pending":
                    fatal("error in response from %s: %s" % (vaultserver, errors[0]))
                if options.debug:
                    log("authorization pending, trying again")
            else:
                # good reply
                break

        if options.registerssh:
            try:
                agent = paramiko.Agent()
            except Exception as e:
                efatal("Error checking for ssh-agent keys", e)
            agent_keys = agent.get_keys()
            if len(agent_keys) == 0:
                fatal("No ssh-agent keys found to register")
            if showprogress:
                log("Registering ssh keys at " + vaultserver + " ...", end='', flush=True)
            pubkeys = []
            keynum = 0
            for key in agent_keys:
                keynum += 1
                keyname = 'key' + str(keynum)
                pubkeys.append(key.get_name() + ' ' + key.get_base64() + ' ' + keyname)

            if 'auth' not in response:
                fatal("no 'auth' in response from %s" % vaultserver)
            auth = response['auth']
            if 'client_token' not in auth:
                fatal("no 'client_token' in response from %s" % vaultserver)
            vaulttoken = auth['client_token']
            headers = {'X-Vault-Token': vaulttoken}

            if options.verbose:
                log("Registering ssh keys at " + vaultserver)
                for pubkey in pubkeys:
                    log("  " + pubkey)

            path = '/v1/' + options.sshpath + '/role/' + credkey
            url = vaultserver + path
            data = {
                'public_keys': pubkeys
            }
            try:
                resp = vault.request(path, headers=headers, data=json.dumps(data).encode())
            except Exception as e:
                if showprogress:
                    log(" failed")
                efatal("ssh key registration failed to %s failed" % vaultserver, e)
            if showprogress:
                log(" done")


        vaulttoken = getVaultToken(vaulttokensecs, response)
        writeTokenSafely("vault", vaulttoken, vaulttokenfile)
        if options.nobearertoken:
            sys.exit(0)

        auth = response['auth']
        if 'metadata' not in auth:
            fatal("no 'metadata' in response from %s" % vaultserver)
        metadata = auth['metadata']
        if options.credkey is None:
            if 'credkey' not in metadata:
                fatal("no 'metadata' in response from %s" % vaultserver)
            credkey = metadata['credkey']

            if options.verbose:
                log("Saving credkey to %s: %s" % (configfile, credkey))
            elif showprogress:
                log("Saving credkey to %s" % configfile)
            try:
                os.makedirs(os.path.expanduser(options.configdir), exist_ok=True)
            except Exception as e:
                efatal('error creating %s' % options.configdir, e)
            try:
                with open(configfile, 'w') as file:
                    file.write(credkey + '\n')
            except Exception as e:
                efatal('error writing %s' % configfile, e)

        if 'oauth2_refresh_token' not in metadata:
            fatal("no 'oauth2_refresh_token' in response from %s" % vaultserver)
        refresh_token = metadata['oauth2_refresh_token']
        fullsecretpath = secretpath.replace("%credkey", credkey)

        if options.verbose:
            log("Saving refresh token to " + vaultserver)
            log("  at path " + fullsecretpath)
        elif showprogress:
            log("Saving refresh token ...", end='', flush=True)
        path = '/v1/' + fullsecretpath
        url = vaultserver + path
        headers = {'X-Vault-Token': vaulttoken}
        storedata = {
            'server': options.issuer,
            'refresh_token': refresh_token
        }
        data = json.dumps(storedata)
        if options.debug:
            log("Refresh token url is", url)
            log("##### Begin refresh token storage data")
            log(data)
            log("##### End refresh token storage data")
        try:
            resp = vault.request(path, headers=headers, data=data.encode())
        except Exception as e:
            if showprogress:
                log(" failed")
            efatal("Refresh token storage to %s failed" % vaultserver, e)
        if showprogress:
            log(" done")

        if options.verbose:
            log("Getting bearer token from " + vaultserver)

        bearertoken = getBearerToken(vaulttoken, fullsecretpath, None)

    if bearertoken is None:
        fatal("Failure getting token from " + vaultserver)

    # Write bearer token to outfile
    writeTokenSafely("bearer", bearertoken, outfile)


if __name__ == '__main__':
    main()
