import argparse
import gc
import sys
import logging

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.ldap import ldap
from impacket.examples import logger
from impacket import version

class ldap_Shell:
    def __init__(self, domain, baseDN, username, password, address, options):
        self.domain = domain
        self.baseDN = baseDN
        self.username = username
        self.password = password
        self.lmhash = ''
        self.nthash = ''
        self.address = address
        self.ldaps_flag = ''
        self.gc_flag = ''

        if options.ldaps == True:
            self.ldaps_flag = True
        
        if options.gc == True:
            self.gc_flag = True

        if options.hashes is not None:
            self.lmhash, self.nthash = options.hashes.split(':')
    
    def ldap_connect(self):
        if self.ldaps_flag is True:
            print("[+] Connecting ldap server over ssl (ldaps)")
            ldapConnection  = ldap.LDAPConnection('ldaps://%s' % self.domain , self.baseDN, self.address)
        elif self.gc_flag is True:
            print("[+] Connecting ldap server over global catalog (GC)")
            ldapConnection  = ldap.LDAPConnection('gc://%s' % self.domain, self.baseDN, self.address)
        else:
            print("[+] Connecting ldap server without any special")
            ldapConnection  = ldap.LDAPConnection('ldap://%s' % self.domain, self.baseDN, self.address)
        
        ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)

        return ldapConnection

    def dummySearch(self, ldapConnection):
        # Let's do a search just to be sure it's working
        searchFilter = "(&(objectclass=person)(sAMAccountName=xiaoli))"

        resp = ldapConnection.search(
            searchFilter=searchFilter
        )
        for item in resp:
            print(item.prettyPrint())

if __name__ == '__main__':
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "impacket LDAP shell")

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-ldaps', action='store_true', help='Connect ldap server over ldaps, port 636')
    group.add_argument('-gc', action='store_true', help='Connect ldap server over gc, port 3268')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    
    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    domain, username, password, address = parse_target(options.target)
    
    try: 
        if domain == '':
            print("[-] Domain need to be specify.")
            sys.exit(0)

        if options.aesKey is not None:
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")
            
        baseDN = ''
        domainParts = domain.split('.')
        for i in domainParts:
            baseDN += 'dc=%s,' % i
        # Remove last ','
        baseDN = baseDN[:-1]
        
        ldap_connector = ldap_Shell(domain, baseDN, username, password, address, options)
        ldap_session = ldap_connector.ldap_connect()
        ldap_connector.dummySearch(ldap_session)
        

    except (Exception, KeyboardInterrupt) as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
    sys.exit(0)

    