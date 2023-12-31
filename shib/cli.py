"""Usage: aws-federated-auth

Script (get-aws-creds) written by batzel@upenn.edu 20180110
Script (aws-federated-auth) modified by jdenk@upenn.edu 20191001
Script (aws-federated-auth) modified by bug@upenn.edu 20191101

Generate aws credentials file for federated logins, with Duo token.

Example:
$ python3 aws-federated-auth
Updated profile aws-ts-isc-awsIAMShibbFull
Updated profile aws-ts-isc-awsIAMShibbIAM
Updated profile aws-sharedservices-isc-awsIAMShibbFull
Updated profile aws-apps-isc-awsIAMShibbFull
Updated profile aws-apps-isc-awsIAMShibbIAM
$ aws --profile aws-apps-isc-awsIAMShibbFull ec2 describe-instances

Based on samlapi_formauth.py script provided at:
https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/

Session tokens default to 1 hour or the max set by the role in AWS. Up
to 12 hours.

This script will save your Shibboleth/Cosign/Duo cookies, so running it
again will try to re-use the saved ones. If they work, you get another
session token. If they don't work, it asks you to authenticate again
and saves the new cookies.

You can set environment variables to change default behaviors.
COOKIEJAR:  filename to store session cookies in for potential re-use
            Defaults to ~/.get-aws-creds.cookies
AWSCREDFILE: filename to store the credentials in. Usually
            ~/.aws/credentials (default)
REGION:     defaults to us-east-1. AWS region to get credentials for
IDPURL:     defaults to http://aws.cloud.upenn.edu, the entry into the
            web auth for saml assertions to log into the AWS console as
            a federated user.
DEBUG:      Used to spit out some additional debugging information, in
            case things aren't working right.

Argument parser values are also available from the --help command.

The credentials file will have new profiles added/updated, named after
the roles that Shibboleth gives you access to. You can then use these
profile names with the aws cli commands etc.

Boto3 users can create a profile session:
profile = boto3.session.Session(profile=<profilename>)
ec2 = profile.client("ec2")

Windows users: Either use "--profile <profilename>" at the end of the
command, or run "set AWS_PROFILE=profilename" to set an environment
variable.


"""

#Requirements for Shib Processing
import os
import base64
import getpass
import logging
import requests

import sys
import argparse
import configparser
from os.path import expanduser
from shib import awsshib

logger = logging.getLogger(__name__)
logger.setLevel(level=os.environ.get("LOGLEVEL", "INFO"))
logger.propagate = False
log_channel = logging.StreamHandler()
formatter = logging.Formatter('{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)8s","message":"%(message)s"}',"%Y-%m-%d %H:%M:%S")
log_channel.setFormatter(formatter)
logger.addHandler(log_channel)


def main():
    """Main: Set up variables argparse, failing back to environment variables.
    Try to use old cookies to reauthenticate, failing that get authentication
    info. Take SAML assertion, use it to get the AWS STS token for each
    available role. Save them in an aws config file.
    """

    parser = argparse.ArgumentParser(
        description="Access ISC Shibboleth Federated Authentication to AWS."
    )
    parser.add_argument('--account',
        help='Filter profile response by account number.'
        ' Check multiple accounts by added then with space separation.',
        nargs='+')
    parser.add_argument('--rolename',
        help='Filter response by Role Name.'
        ' Ignores case and does substring match. Only value allowed.')
    parser.add_argument('--list',
        help= 'Don\'t generate profiles, just list'
        ' available options passing filters.',
        action='store_true')
    parser.add_argument('--assertionconsumer',
        help='The shibboleth protected site you want to log into.'
        ' Defaults to https://signin.aws.amazon.com/saml'
    )
    parser.add_argument('--idpentryurl',
        help='The ECP endpoint for the IDP.'
        ' Defaults to https://idp.pennkey.upenn.edu/idp/profile/SAML2/SOAP/ECP'
    )
    parser.add_argument('--duofactor',
        help='The MFA factor to use, can be one of "auto", "push", "phone", or "passcode".'
        ' Defaults to "auto".',
        choices=['auto','push','phone','passcode']
    )
    parser.add_argument('--awsconfigfile',
        help='Filename to store the aws session credentions for potential'
        ' re-use. If unset AWSCONFIGFILE environment variables will be used,'
        ' otherwise, ~/.aws/credentials')
    parser.add_argument('--sslverification',
        help='Controls if SSL confirmation of certs is used.'
        ' Defaults to true.',
        type=bool,
        default=True)
    parser.add_argument('--outputformat',
        help='Select the format of output responses.'
        ' If unset will use AWS_DEFAULT_OUTPUT environment variable,'
        ' otherwise "json"',
        choices=['text', 'table', 'json'])
    parser.add_argument('--region',
        help='Select the region to connect to.'
        ' If unset will user AWS_DEFAULT_REGION environment variable,'
        ' otherwise, "us-east-1"')
    parser.add_argument('--cookiejar',
        help='Filename to store session cookies for potential re-use.'
        ' If unset COOKIEJAR environment variables will be used,'
        ' otherwise, ~/.aws-federated-auth.cookies')
    parser.add_argument('--logging',
        help='Set log level. IF DEBUG environment value set, use that.'
        ' otherwise, "INFO"',
        choices=['critical', 'warning', 'error','info','debug'])
    parser.add_argument('--duration',
        help='Duration before timeout of session in seconds.'
        ' Defaults to 1 hour / {0} seconds, min {1} max 12 hours / {2} '
        'seconds.'.format(str(60*60),str(60*15),str(60*60*12)))
    parser.add_argument('--storepass',
        help='Store the password to the system keyring service and retrieve on following requests'
        ' If unset you will be prompted for password on every request',
        action='store_true')
    parser.add_argument('--user',
        help='Login as this user'
        ' If unset you will be prompted for user')

    args = parser.parse_args()
    # Variables

    # set DEBUG to enable debug logging
    #logging.basicConfig(level=logging.INFO)
    level = None
    if args.logging:
        log_level = args.logging.upper()
        level = logging.getLevelName(args.logging.upper())
    else:
        log_level = 'INFO'
    if level:
        logger.setLevel(level)

    if args.list:
        logger.debug("Selected to only list results, rather than"
            " update profiles and tokens")

    if args.account:
        logger.debug("Selected to filter by account with the"
        " following values: {0}".format(args.account))

    if args.rolename:
        logger.debug("Selected to filter by role containing the"
        " following {0}".format(args.rolename))

    if args.duration:
        session_duration = int(args.duration)
        if 60*60*12 < session_duration <= 0:
            raise argparse.ArgumentTypeError("%s is an invalid number"
        " of seconds" % args.duration)

    if args.cookiejar:
        cookiejar_filename = args.cookiejar
    else:
        env_default = "{0}/.aws-federated-auth.cookies".format(expanduser("~"))
        cookiejar_filename = os.getenv("COOKIEJAR", env_default)
    logger.debug("cookiejar_filename: {0}".format(cookiejar_filename))

    # The default AWS region that this script will connect
    # to for all API calls
    if args.region:
        region = args.region
    else:
        region = os.getenv("AWS_DEFAULT_REGION",'us-east-1')
    logger.debug("region: {0}".format(region))

    # output format: The AWS CLI output format that will be configured in the
    # saml profile (affects subsequent CLI calls)
    if args.outputformat:
        outputformat = args.outputformat
    else:
        outputformat = os.getenv("AWS_DEFAULT_OUTPUT",'json')
    #logger.debug("outputformat: {0}".format(outputformat))

    # awsconfigfile: The file where this script will store the temp
    # credentials under the saml profile
    config_default = "{0}/.aws/credentials".format(expanduser("~"))
    if args.awsconfigfile:
        awsconfigfile = args.awsconfigfile
    else:
        awsconfigfile = os.getenv('AWS_SHARED_CREDENTIALS_FILE', config_default)
    # Make directory for aws credentials file if it does not exist
    if not os.path.exists(awsconfigfile): 
        os.makedirs(expanduser(os.path.dirname(awsconfigfile)), exist_ok=True)
        # Removing this since it means we create a 0 byte credentials file if we hit an exception later
        # with open(expanduser(awsconfigfile), 'w'):
        #     pass

    logger.debug("awsconfigfile: {0}".format(awsconfigfile))

    # SSL certificate verification: Whether or not strict certificate
    # verification is done, False should only be used for dev/test
    sslverification = args.sslverification
    logger.debug("sslverification: {0}".format(sslverification))

    # 
    if args.assertionconsumer:
        consumer = args.assertionconsumer
    else:
        consumer = os.getenv("CONSUMER", 'https://signin.aws.amazon.com/saml')
    logger.debug("assertionconsumer: {0}".format(consumer))

    # idpentryurl: The initial url that starts the authentication process.
    if args.idpentryurl:
        idpentryurl = args.idpentryurl
    else:
        idpentryurl = os.getenv("IDPURL", 'https://idp.pennkey.upenn.edu/idp/profile/SAML2/SOAP/ECP')
    logger.debug("idpentryurl: {0}".format(idpentryurl))

    # allow selection of duo authentication factor method
    if args.duofactor:
        duofactor = args.duofactor
    else:
        duofactor = "auto"

    if args.user:
        username = args.user
    else:
        print("Username:", end=' ')
        username = input()

    try:
        import keyring
    except ImportError:
        keyring = None

    password = None
    password_stored = False

    if keyring is not None:
        try:
            password = keyring.get_password("aws-federated-auth", "password")
        except Exception:
            logger.warning("No recommended backend for keyring was available --storepass functionality will not be available")


    if password is None:
        password = getpass.getpass()
        if args.storepass:
            if keyring is not None:
                keyring.set_password("aws-federated-auth", "password", password)
                password_stored = True
            else:
                logger.error("Keyring dependency is not included - in order to use 'storepass' you need to run pip "
                             "install keyring first")
    if password is None:
        print("You must provide a password in order to sign in")
    else:
        print("Processing authorization, this takes longer the more access you have selected.")
        AWSCreds = awsshib.AWSAuthorization(
            username=username,
            password=password,
            assertionconsumer=consumer,
            idpentryurl=idpentryurl,
            duo_factor=duofactor,
            region=region,
            output_format=outputformat,
            config_file=awsconfigfile,
            cookiejar_filename=cookiejar_filename,
            loglevel=log_level)

        auth_args = {}
        if args.rolename:
            auth_args['role_name'] = args.rolename

        try:
            if args.account:
                for account in args.account:
                    auth_args['account_number'] = account
                    AWSCreds.authorize(**auth_args)
            if not args.account:
                if auth_args:
                    AWSCreds.authorize(**auth_args)
                else:
                    AWSCreds.authorize()
        except ValueError:
            print("Unable to parse SAML assertions - this is probably because your password is incorrect or you failed to "
                  "approve your Duo request")
            if password_stored and keyring is not None:
                keyring.delete_password("aws-federated-auth", "password")


if __name__ == "__main__":
    main()
