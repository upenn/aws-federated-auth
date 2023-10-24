"""
    The ECPShib classes allow for navigating ECP authorization from a SAML IDP.

    Based on components of the: 
        get-aws-creds creds written by batzel@upenn.edu 20180110

    Used to step through a shibboleth authentication via ECP and generate two assets
    1.) a requests session that can be used for futher auth.
    2.) an ECP response that can be converted into a SAML assertion.

    Supports duo auth and storing sessions as pickles for reuse.


"""

__author__ = "Jim Denk <jdenk@wharton.upenn.edu>"
__version__ = "1.0.1"

#Requirements for Shib Processing
import os
import logging
import requests
import pickle
import xml.etree.ElementTree as ET
from uuid import uuid4
from urllib.parse import urlparse, urlunparse
import datetime

logger = logging.getLogger(__name__)
logger.setLevel(level=os.environ.get("LOGLEVEL", "INFO"))
logger.propagate = False
log_channel = logging.StreamHandler()
formatter = logging.Formatter('{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)8s","message":"%(message)s"}',"%Y-%m-%d %H:%M:%S")
log_channel.setFormatter(formatter)
logger.addHandler(log_channel)

class ECPShib(object):
    """ Session handler for SAML ECP implementation  
    for federated Amazon Web Services auth.
    """

    def __init__(
        self, 
        idpentryurl,
        username,
        password,
        assertionconsumer="https://signin.aws.amazon.com/saml",
        duo_factor=None,
        cookiejar_filename=None, 
        tossoldcookies=True, 
        sslverification=True,
        loglevel=None
    ):
        """ Instantiates an instance of PennShib. """
        self.data = None
        
        # Set attributes necessary for API
        self.idpentryurl = idpentryurl
        self.assertionconsumer = assertionconsumer
        self.username = username
        self.password = password
        self.cookiejar_filename = cookiejar_filename
        self.tossoldcookies = tossoldcookies
        self.sslverification = sslverification
        self.ns = {
            'S': 'http://schemas.xmlsoap.org/soap/envelope/',
            'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
        }
        self.session = None
        self.ecp_response = None
        self.assertion = None
        factors = ['auto', 'push', 'passcode', 'phone']
        if duo_factor:
            if duo_factor in factors:
                self.duo_factor = duo_factor
            else:
                logger.warning(f"Duo factor of {duo_factor} is not a valid value in {factors}. 'Auto' will be used instead.")
                self.duo_factor = "auto"
        else:
            self.duo_factor = "auto"
        if loglevel:
            logger.setLevel(logging.getLevelName(loglevel.upper()))

    def save_cookies(self):
        """ Save requests module's cookiejar as jarfilename """
        with open(self.cookiejar_filename, 'wb') as f:
            pickle.dump(self.session.cookies, f)
            logger.debug("Dumped a pickle.")

    def load_cookies(self):
        """ Load pickled cookiejar from jarfilename to use with requests 
        module calls. Allows for reuse of sessions while SSO session persists.
        Useful for avoiding extra MFA requests.
        """
        with open(self.cookiejar_filename, 'rb') as f:
            logger.debug("Loaded a pickle")
            return pickle.load(f)

    def get_saml_payload(self):
        """
        Generates an ECP SAML AuthNRequest for the Amazon SP.
        Returns:
            A SOAP byte string.
        """
        logger.debug(f"structuring the datetime from utcnow")
        now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        logger.debug(f"generating a UUID")
        uuid = '_' + str.upper(str(uuid4())).replace('-', '')

        #Construct an XML namespace as recommended https://docs.python.org/3/library/xml.etree.elementtree.html
        ns = {
            'S': 'http://schemas.xmlsoap.org/soap/envelope/',
            'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
        }
        for key, value in self.ns.items():
            ET.register_namespace(key, value)

        #apply schema data to tags element - 'envelope' and subelement - 'body'
        envelope = ET.Element(ET.QName(self.ns['S'],"Envelope"))
        body = ET.SubElement(envelope, ET.QName(self.ns['S'],"Body"))

        attr = {
            'AssertionConsumerServiceURL': self.assertionconsumer,
            'ID': uuid,
            'IssueInstant': now,
            'ProtocolBinding': "urn:oasis:names:tc:SAML:2.0:bindings:PAOS",
            'Version': '2.0',
        }
        authn_request = ET.SubElement(body, ET.QName(self.ns["saml2p"], "AuthnRequest"), **attr)

        issuer = ET.SubElement(authn_request, ET.QName(self.ns["saml2"], "Issuer"))
        issuer.text = "urn:amazon:webservices"
        logger.debug(f"SAML assertion payload: {ET.tostring(envelope)}")
        self.saml_payload = ET.tostring(envelope)

    def call_consumer(self, checkcookie=False):
        logger.debug(F"Calling consumer endpoint {self.assertionconsumer} to verify access. (using file cookies: {checkcookie})")
        if checkcookie:
            self.load_cookies()
        try:
            session_test = self.session.get(self.assertionconsumer)
            if session_test == 200:
                logger.debug(f"Consumer endpoint {self.assertionconsumer} called successfully from session")
                return True
            elif checkcookie and self.cookiejar_filename:
                return self.call_consumer(checkcookie=True)
            else:
                return False
        except Exception:
            raise ValueError

    def ecp_auth(self):
        """ Walk through the ECP flow, negotiating Authentication and MFA if necessary """
        
        #check for existing session, if it's valid, nothing to do.

        logger.debug("Calling the assertion consumer endpoint with session data, not using cookies.")

        if not self.call_consumer():
            logger.debug("Current session can't access consumer endpoint walking through ECP SAML call.")

            #configure the payload for SAML auth
            self.get_saml_payload()

            logger.debug(f"Calling the shibboleth ECP endpoint at {self.idpentryurl}")
            try:
                headers = {'Content-Type': 'text/xml', 'charset': 'utf-8'}
                logger.debug(f"Duo factor set to {self.duo_factor} for authentication call.")
                if self.duo_factor:
                    headers["X-Shibboleth-Duo-Factor"] = self.duo_factor
                if self.duo_factor == "passcode":
                    duo_passcode = input('Code:')
                    headers["X-Shibboleth-Duo-Passcode"] = duo_passcode
                auth = (self.username, self.password)
                logger.debug(f"Precall cookies: {self.session.cookies}")
                response = self.session.post(self.idpentryurl, headers=headers, data=self.saml_payload, auth=auth, timeout=30)
                logger.debug(f"Postcall cookies: {self.session.cookies}")
                if response.status_code == 200:
                    # Now determine if a bad username and/or password was entered
                    logger.debug("Decoding response")
                    root = ET.fromstring(response.content.decode())
                    ns = {
                        'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
                        'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
                        'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
                    }
                    # this path was mapped out from actual SOAP responses
                    status = root.find(
                        './soap:Body'
                        '/saml2p:Response'
                        '/saml2p:Status'
                        '/saml2p:StatusCode'
                        '/saml2p:StatusCode',
                        ns,
                    )
                    # if a bad username/password was entered, print a message to the user and exit(1)
                    if status is not None and 'status:AuthnFailed' in status.attrib['Value']:
                        print("Authentication Failed, exiting, nothing done")
                        exit(1)
                    #logger.debug(f"Status {status.attrib['Value']}")
                    logger.debug("Authenticated Successfully")
                    self.ecp_response = response.text

                elif response.status_code == 500:
                    logger.debug("Not Authorized")
                else:
                    logger.debug(f"Authentication failed with status code: {response.status_code}")
            except Exception:
                raise ValueError
        else:
            logger.debug("Current session data able to call consumer endpoint, no ECP SAML call necessary.")
    
    def negotiate(self):
        """Given a IDP Entry URL, handle cookies and do the shibboleth dance.
        Return a shibboleth assertion for the service invoking. Configure your
        cookiejar to handle your session status for reuse.
        """

        # set trigger to see if we've tried a new session
        if self.cookiejar_filename:
            self.load_cookies
        
        if not self.session:
            self.session = requests.session()

        self.ecp_auth()
            
        return self.ecp_response, self.session


