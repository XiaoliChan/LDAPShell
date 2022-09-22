import argparse
import sys
import logging
import ldap3
import ldapdomaindump
import ssl

from impacket import LOG
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from utils.ldap_shell import LdapShell
#from impacket.examples.ldap_shell import LdapShell

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

        if options.ldaps == True:
            self.ldaps_flag = True

        if options.hashes is not None:
            self.lmhash, self.nthash = options.hashes.split(':')
            if self.lmhash == "":
                self.lmhash = "aad3b435b51404eeaad3b435b51404ee"
    
    def ldap_connection(self, tls_version):
        user_withDomain = '%s\\%s' % (self.domain, self.username)
        if tls_version is not None:
            use_ssl = True
            port = 636
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
        else:
            use_ssl = False
            port = 389
            tls = None
        ldap_server = ldap3.Server(self.address, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
        if self.nthash != "":
            ldap_session = ldap3.Connection(ldap_server, user=user_withDomain, password=self.lmhash + ":" + self.nthash, authentication=ldap3.NTLM, auto_bind=True)
        else:
            ldap_session = ldap3.Connection(ldap_server, user=user_withDomain, password=self.password, authentication=ldap3.NTLM, auto_bind=True)
        return ldap_server, ldap_session

    # For ldap3 with tls mode(only for ldap3).
    # Picked function from rbcd.py
    def ldap_sessions(self):
        if self.ldaps_flag == True:
            try:
                return self.ldap_connection(tls_version=ssl.PROTOCOL_TLSv1_2)
            except ldap3.core.exceptions.LDAPSocketOpenError:
                return self.ldap_connection(tls_version=ssl.PROTOCOL_TLSv1)
        else:
            return self.ldap_connection(tls_version=None)

    def start_LDAPShell(self, ldap_server, ldap_session):
        domainDumpConfig = ldapdomaindump.domainDumpConfig()
        domainDumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, domainDumpConfig)
        ldap_shell = LdapShell(self.baseDN, domainDumper, ldap_session)
        ldap_shell.cmdloop()

if __name__ == '__main__':
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "impacket LDAP shell")

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    '''
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                         '(128 or 256 bits)')
    '''
    group.add_argument('-ldaps', action='store_true', help='Connect ldap server over ldaps, port 636')

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
        '''
        if options.aesKey is not None:
            options.k = True
        '''
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
        ldap_server, ldap_session = ldap_connector.ldap_sessions()
        ldap_connector.start_LDAPShell(ldap_server, ldap_session)

    except (Exception, KeyboardInterrupt) as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
    sys.exit(0)

    