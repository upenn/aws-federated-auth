"""
    The AWS authorization class allow for parsing a shibboleth assertion and 
    managing AWS roles that the user can adopt.

    Based on components of the: 
        get-aws-creds creds written by batzel@upenn.edu 20180110



"""

__author__ = "Jim Denk <jdenk@wharton.upenn.edu>"
__version__ = "1.0.0"

import os
from shib import ecpshib
import logging
import xml.etree.ElementTree as ET
import re
import boto3
import configparser
from base64 import b64encode

logger = logging.getLogger(__name__)
logger.setLevel(level=os.environ.get("LOGLEVEL", "INFO"))
logger.propagate = False
log_channel = logging.StreamHandler()
formatter = logging.Formatter('{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)8s","message":"%(message)s"}',"%Y-%m-%d %H:%M:%S")
log_channel.setFormatter(formatter)
logger.addHandler(log_channel)

class AWSRole(object):
    """ Instantiates a role object """
    def __init__(
        self,
        principal_arn,
        role_arn,
        role_name,
        profile_name,
        account_number,
        token=None,
        boto_session=None,
        iam_session=None,
        sts_session=None,
        max_duration=3600
    ):
        self.principal_arn = principal_arn
        self.role_arn = role_arn
        self.role_name = role_name
        self.profile_name = profile_name
        self.account_number = account_number
        self.token = token
        self.boto_session = boto_session
        self.iam_session = iam_session
        self.sts_session = sts_session
        self.max_duration = max_duration

    def __eq__(self, other): 
        """ set equality comparison """
        if not isinstance(other, AWSRole):
            # don't attempt to compare against unrelated types
            return NotImplemented
        return(
            self.principal_arn == other.principal_arn 
            and self.role_arn == other.role_arn 
            and self.role_name == other.role_name 
            #and self.profile_name == other.profile_name 
            and self.account_number == other.account_number
        )

    def get_token(self, assertion, region):
        """ get STS token from AWS for role """
        try:
            self.sts_session = boto3.client('sts', region_name=region)
            self.token = self.sts_session.assume_role_with_saml(
                DurationSeconds=self.max_duration,
                RoleArn=self.role_arn,
                PrincipalArn=self.principal_arn,
                SAMLAssertion=assertion
            )   
        except:
            logger.warning("failed to establish STS connection for profile {0}".format(self.profile_name))
            #raise ValueError
    
    def get_session(self, region):
        """ establish an AWS session """
        if self.token:
            try:
                self.boto_session = boto3.Session(
                    aws_access_key_id=self.token['Credentials']['AccessKeyId'],
                    aws_secret_access_key=self.token['Credentials']['SecretAccessKey'],
                    aws_session_token=self.token['Credentials']['SessionToken'],
                    region_name=region
                )
            except:
                raise ValueError
        else:
            logger.warning("no token associated with role with which to generate session.")
    
    def get_iam_session(self, region):
        """ establish an IAM session """
        if not self.boto_session:
            self.get_session(region)
        else:
            try:  
                self.iam_session = self.boto_session.client(
                        'iam', 
                        region_name=region
                    )
            except:
                logger.warning("Failed to create iam session. Likely not authorized")
                raise ValueError

    def get_duration(self, region):
        """ get maximum duration for role """
        if self.token:
            if not self.iam_session:
                self.get_iam_session(region)
            try:
                logger.debug("Attempting to query max duration")
                self.max_duration = self.iam_session.get_role(RoleName=self.role_name)['Role']['MaxSessionDuration']
            except:
                logger.debug("Failed to query max duration")
                raise ValueError
        else:
            logger.warning("no token associated with role with which to generate session and configure duration.")

class AWSAccount(object):
    """ Instantiates an account object """
    def __init__(
        self,
        account_number,
        aws_roles=[],
        account_alias=None
    ):
        self.account_number = account_number
        self.aws_roles = aws_roles
        self.account_alias = account_alias

    def __eq__(self, other): 
        """ set equality comparison """
        if not isinstance(other, AWSAccount):
            # don't attempt to compare against unrelated types
            return NotImplemented
        return(
            self.account_number == other.account_number
            and self.aws_roles == other.aws_roles
        )

    def get_roles(self,**kwargs):
        """ query roles from an account """
        return_roles = [] 
        if kwargs:
            for key, value in kwargs.items():
                for role in self.aws_roles:
                    logger.debug("{0},{1}:{2}".format(getattr(role,key),key,value.lower()))
                    if value.lower() in getattr(role,key).lower():
                        logger.debug("Returning role for {0}: {1}".format(key, value))
                        return_roles.append(role)
            if not return_roles:
                logger.debug("No match on {0}: {1}".format(key, value))
        return return_roles
    
    def set_alias(self,region):
        """ attempt to read account alias with available roles """
        account_alias = None
        for role in self.aws_roles:
            if not role.iam_session:
                role.get_iam_session(region)
            if role.iam_session:
                try:
                    check_aliases = role.iam_session.list_account_aliases()['AccountAliases']
                    if check_aliases:
                        account_alias = check_aliases[0]
                    if account_alias:
                        self.account_alias = account_alias
                        break
                except:
                    logger.debug("no alias returned")
        if self.account_alias:
            for role in self.aws_roles:
                role.profile_name = role.profile_name.replace(
                    self.account_number, 
                    self.account_alias,
                    1
                )

class AWSAuthorization(ecpshib.ECPShib):
    """ Instantiates an instance of AWSAuthorization.  """
    def __init__(
        self,
        idpentryurl,
        username,
        password,
        region,
        config_file,
        assertionconsumer="https://signin.aws.amazon.com/saml",
        duo_factor=None,
        cookiejar_filename=None,
        output_format = "json",
        tossoldcookies=True,
        sslverification=True,
        writeheader=False,
        loglevel="INFO"
    ):
        ecpshib.ECPShib.__init__(
            self,
            idpentryurl,
            username,
            password,
            assertionconsumer,
            duo_factor,
            cookiejar_filename,
            tossoldcookies,
            sslverification,
            loglevel
        )
        self.assertion = None
        self.session = None
        self.ecp_response = None
        self.config_file = config_file
        self.output_format = output_format
        self.region = region
        self.aws_accounts=[]
        self.writeheader=True

        logger.setLevel(logging.getLevelName(loglevel))
        
    def get_account(self, account_number):
        """ query account numbers """
        logger.debug("Checking for account_number: {0}".format(account_number))
        results = None
        for aws_account in self.aws_accounts:
            if account_number == aws_account.account_number:
                results = aws_account
        return results
    
    def append_account(self, account):
        """ append account numbers """
        if account not in self.aws_accounts:
            self.aws_accounts.append(account)

    def accounts_with_role(self,**kwargs):
        """ search accounts for the presence of roles """
        if kwargs:
            return_accounts = []
            for key, value in kwargs.items():
                for account in self.aws_accounts:
                    logger.debug("Getting {0}: {1} from {2}".format(key, value, account.account_number))
                    roles = account.get_roles(**{key:value})
                    if roles:
                        account.aws_roles = roles
                        return_accounts.append(account)
            return return_accounts   

    def get_aws_authorization(self):
        """ Read the ECP Response to determine our authorization options """
        logger.debug("Doing the XML dance to encode"
            " the assertion and identify roles.")
        logger.debug(self.ecp_response)
        #hacky string parsing because elementtree is transforming the data in a breaking manner avoid lxml dependency
        assertion_text = self.ecp_response.split('<soap11:Body>')[1].split('</soap11:Body>')[0]
        root = ET.fromstring(self.ecp_response)
        saml_response = root.find('S:Body/saml2p:Response', self.ns)
        self.assertion = b64encode(assertion_text.encode('utf-8')).decode("us-ascii")
        logger.debug(self.assertion)
        assertion_roles = []

        for xml_role in  saml_response.findall("saml2:Assertion/saml2:AttributeStatement/saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml2:AttributeValue", self.ns):
            assertion_roles.append(ET.tostring(xml_role, encoding="unicode"))

        role_list = []
        #pulls the AWS role into a c
        role_regex = re.compile('.*(arn:aws:iam::([0-9]+):role/([^,:]+)).*<')
        saml_regex = re.compile('.*(arn:aws:iam::([0-9]+):saml-provider/([^,:]+)).*')
        
        for aws_role in assertion_roles:
            role_arn = role_regex.match(aws_role).group(1)
            principal_arn = saml_regex.match(aws_role).group(1)
            role_name = role_arn.split('/')[-1]
            account_number = principal_arn.split(':')[4]
            profile_name = "{0}-{1}".format(account_number,role_name)
            role_list.append(AWSRole(
                role_name=role_name,
                role_arn=role_arn,
                principal_arn=principal_arn,
                profile_name=profile_name,
                account_number=account_number
            ))
        if role_list:
            accounts = set([x.account_number for x in role_list])
            for account in accounts: 
                existing_account = self.get_account(account_number=account)
                if existing_account:
                    existing_roles = existing_account.aws_roles
                    new_roles = [x for x in role_list if x.account_number == account]
                    for role in new_roles:
                        if role not in existing_roles:
                            existing_roles.append(role)
                    existing_account.aws_roles = existing_roles
                    self.aws_accounts = [existing_account if x.account_number==existing_account.account_number else x for x in self.aws_accounts]
                        
                else:
                    logger.debug("creating account {0} to append".format(account))
                    new_account = AWSAccount(account_number=account)
                    new_account.aws_roles = [x for x in role_list if x.account_number == account]
                    self.append_account(new_account)
        else:
            logger.debug("No roles returned")    

    def display_roles(self, access_list):
        """ Output function for commandline display """
        if access_list:
            template = "{0:65} {2:14} {3:12}" 
        else:
            template = "{0:65} {1:12} {2:14} {3:12}"
        header = template.format(
            "profile_name".replace("_"," ").upper(),
            "max_duration".replace("_"," ").upper(),
            "account_number".replace("_"," ").upper(),
            "role_name".replace("_"," ").upper()
        )

        if self.writeheader:
            print(header)
            self.writeheader = False

        for account in self.aws_accounts:
            for aws_role in account.aws_roles:
                if aws_role.token:
                    print(
                        template.format(
                            aws_role.profile_name,
                            aws_role.max_duration,
                            account.account_number,
                            aws_role.role_name
                        )
                    )

    def write_profile(self):
        """ Output function for profile writing """
        file_name = self.config_file
        logging.debug("Reading existing config file."
            " Expecting: {0}".format(file_name))
        config = configparser.RawConfigParser()
        config.read(file_name)
        for account in self.aws_accounts:
            for aws_role in account.aws_roles:
                # Put the credentials into a saml specific section instead of clobbering
                # the default credentials
                if aws_role.token:
                    if not config.has_section(aws_role.profile_name):
                        logger.debug("Adding new profile section: {0}".format(aws_role.profile_name))
                        config.add_section(aws_role.profile_name)
                    config.set(aws_role.profile_name, 'output', self.output_format)
                    config.set(aws_role.profile_name, 'region', self.region)
                    config.set(aws_role.profile_name, 'aws_access_key_id', aws_role.token['Credentials']['AccessKeyId'])
                    config.set(aws_role.profile_name, 'aws_secret_access_key', aws_role.token['Credentials']['SecretAccessKey'])
                    config.set(aws_role.profile_name, 'aws_session_token', aws_role.token['Credentials']['SessionToken'])

        # Write the updated config file
        with open(file_name, 'w+') as configfile:
            config.write(configfile)
    
    def authorize(
        self,
        role_name=None,
        account_number=None,
        access_list=False,
        duration=None,
        silent=False
    ):
        """ Function to navigate authorization """
        if not self.assertion:
            logger.debug("No assertion, negotiating.")
            self.negotiate()
        try:
            logger.debug("Authorization first attempt.")
            self.get_aws_authorization()
        except:
            logger.debug("Renegotiate. Authorization second attempt.")
            self.negotiate()
            self.get_aws_authorization()
            

        if not self.aws_accounts:
            self.writeheader = True

        if account_number:
            filtered = self.get_account(account_number=account_number)
            if filtered:
                self.aws_accounts = [filtered]
            else:
                self.aws_accounts = []
        if role_name:
            filtered = self.accounts_with_role(role_name=role_name)
            if filtered:
                logger.debug("Accounts filtered on role: {0}".format(role_name))
                self.aws_accounts = filtered
            else:
                self.aws_accounts = []

        if self.aws_accounts:
            if not access_list:
                for account in self.aws_accounts:
                    logger.debug(account.account_number)
                    for aws_role in account.aws_roles:
                        logger.debug("{0:4}".format(aws_role.profile_name))
                        try:
                            if duration: 
                                aws_role.max_duration = duration
                            aws_role.get_token(assertion=self.assertion, region=self.region)
                        except:
                            self.negotiate()
                            aws_role.get_token(assertion=self.assertion, region=self.region)
                        if aws_role.token:
                            try:
                                aws_role.get_session(region=self.region)
                            except:
                                logger.warning("Failed to establist a session for {0}".format(aws_role.profile_name))
                                #raise ValueError
                            try:
                                if not duration:
                                    aws_role.get_duration(region=self.region)
                            except:
                                logger.debug("Failed to get duration")
                            if not duration and aws_role.max_duration != 3600:
                                try:
                                    aws_role.get_token(assertion=self.assertion,region=self.region)
                                except:
                                    self.negotiate()
                                    aws_role.get_token(assertion=self.assertion,region=self.region)
                                try:
                                    aws_role.get_session(region=self.region)
                                except:
                                    raise ValueError
                        else:
                            logger.warning("No sts role token was created so no session can be established")
                    if not account.account_alias:
                        account.set_alias(region=self.region)
                self.write_profile()
                if not silent:
                    self.display_roles(access_list=access_list)
            else:
                if not silent:
                    self.display_roles(access_list=access_list)
