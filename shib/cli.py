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
LOGLEVEL:   Used to spit out some additional debugging information, in
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
import getpass
import logging
import time

import argparse
import configparser
from os.path import expanduser
import shib.constants

logger = logging.getLogger('shib')
logger.setLevel(level=os.environ.get("LOGLEVEL", "ERROR"))
log_channel = logging.StreamHandler()
formatter = logging.Formatter('{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)8s","message":"%(message)s"}',"%Y-%m-%d %H:%M:%S")
log_channel.setFormatter(formatter)
logger.addHandler(log_channel)

def bounded_int(min_value, max_value):
    def _bounded_int(value):
        try:
            int_value = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{value} is not a valid integer") from exc
        if int_value < min_value or int_value > max_value:
            raise argparse.ArgumentTypeError(
                f"{int_value} is out of range [{min_value}, {max_value}]"
            )
        return int_value
    return _bounded_int

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
        ' Check multiple accounts by added them with space separation.',
        nargs='+')
    parser.add_argument('--accountalias',
        help='Filter profile response by account alias.'
        ' This feature is similar to --account, but uses the account alias.'
        ' Check multiple account aliases by added them with space separation.'
        ' You must have previously authenticated in the past to filter by a specific account alias.',
        nargs='+')
    parser.add_argument('--rolename',
        help='Filter response by Role Name.'
        ' Ignores case and does substring match. Only value allowed.')
    parser.add_argument('--profilename',
        help='Filter response by profile name. Check multiple profiles by added them with space separation.'
        ' You must have previously authenticated in the past to filter by a specific profile name.',
        nargs='+')
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
    parser.add_argument('--resetawsconfigfile',
        help='Clear all credentials stored in the aws config file before storing new credentials.'
        ' Not compatible with filtering by account alias or profile name as these filters rely on'
        ' the stored credentials file. Use with caution as this will delete any existing credentials'
        ' stored in the config file, including manually stored credentials. This option is intended'
        ' to be used to clean out cruft and replace corrupted credentials files.',
        action='store_true')
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
    
    ########################## DEBUGGING OPTIONS ##########################
    parser.add_argument(
        "--logging",
        help="Set log level. IF LOGLEVEL environment value set, use that."
        ' otherwise, "ERROR"',
        type=str.lower,
        choices=["critical", "warn", "error", "info", "debug"],
    )
    parser.add_argument(
        "--exceptiontrace",
        help='Shows exception tracebacks in the log output. Defaults to False.',
        action='store_true'
    )
    parser.add_argument(
        "--timer",
        help="Report the duration that the script takes to run, starting from when the password"
        " is entered.",
        action="store_true"
    )
    #######################################################################

    parser.add_argument('--max-duration-limit',
        help='Limit the maximum duration before timeout of session in seconds.'
        ' Minimum is 900 seconds (15 minutes) and maximum is 43200 seconds (12 hours).'
        ' If this limit is higher than the max duration allowed by the role, the max' 
        ' duration of the role will take precedence.',
        type=bounded_int(shib.constants.MaxDurationSeconds.LOWER_LIMIT, shib.constants.MaxDurationSeconds.UPPER_LIMIT),
        default=shib.constants.MaxDurationSeconds.UPPER_LIMIT
    )
    parser.add_argument('--update-max-duration',
        help='Set how aws-federated-auth decides to query and update the stored max duration of a role.'
        ' The default setting of "new" means that the script will only query for the max duration of a role'
        ' if no stored max duration is found for that role in the credentials file or if the stored max duration'
        ' results in an error from AWS. Setting this flag to "all" will make the script update max duration for'
        ' all roles regardless of circumstances. Setting this flag to "none" will make the script never'
        ' update max duration, even if the stored max duration results in an error from AWS.',
        choices=[value.value for value in shib.constants.UpdateMaxDurationOptions],
        default=shib.constants.UpdateMaxDurationOptions.NEW.value,
    )
    parser.add_argument('--update-account-alias',
        help='Set how aws-federated-auth decides to query and update the stored account alias for an account.'
        ' The default setting of "new" means that the script will only query for the account alias if no stored'
        ' account alias is found for that account in the credentials file. Setting this flag to "all" will make'
        ' the script query and update the account alias for all accounts regardless of circumstances. Setting'
        ' this flag to "none" will make the script never update the account alias, even if there is no stored'
        ' account alias.',
        choices=[value.value for value in shib.constants.UpdateAccountAliasOptions],
        default=shib.constants.UpdateAccountAliasOptions.NEW.value,
    )
    parser.add_argument('-Q', '--quick',
        help='Quick mode. Skip both the max duration and account alias checks to speed up authentication.',
        action='store_true'
    )
    parser.add_argument('--storepass',
        help='Store the password to the system keyring service to allow for automatic retrieval'
        ' on following requests. If set, you will be prompted for a password that will then'
        ' be stored in the system keyring service. If unset, the script will attempt to retrieve'
        ' a previously stored password from the system keyring service and then prompt you for'
        ' a password if there is not a stored password.',
        action='store_true')
    parser.add_argument('--user',
        help='Login as this user'
        ' If unset you will be prompted for user')
    parser.add_argument('--sort_display',
        help='Sort the display output. Listing multiple column names will'
        ' sort in ascending order of the column names listed. Defaults to sorting by profile_name.',
        nargs='+',
        choices=['account_number', 'max_duration', 'profile_name', 'role_name'],
        default=['profile_name']
    )
    parser.add_argument('--split_display',
        help='Split the display output with a horizontal line between different groups.'
        ' Multiple columns names can be specified. Defaults to splitting by account_number.',
        nargs='+',
        choices=['account_number', 'max_duration', 'profile_name', 'role_name'],
        default=['account_number']
    )
    parser.add_argument('--install-completion',
        help='Install shell completion script for the specified shell type.'
        ' Specifying this option will prevent AWS authentication from happening for this' \
        ' specific run of the script.',
        choices=['bash', 'omz'])
    parser.add_argument('--completion-location',
        help='Location to install the shell completion scripts.'
        ' Defaults to ~/._aws_profile_complete.sh for bash and'
        ' ~/.oh-my-zsh/completions/_aws_profile_export for oh-my-zsh.'
        ' For omz, be sure that the location is in your $fpath and that the name of the file'
        ' is _aws_profile_export.',
        type=str)

    args = parser.parse_args()
    # Variables

    if args.logging:
        logger.setLevel(logging.getLevelName(args.logging.upper()))

    log_level = logging.getLevelName(logger.getEffectiveLevel())

    # Shell completion script installation
    if args.install_completion:
        from shib import shellcompletion
        logger.info(f"Installing shell completion script for {args.install_completion} shell.")
        shellcompletion_instance = shellcompletion.ShellCompletion(exceptiontrace=args.exceptiontrace)
        shellcompletion_instance.install_completion(
            shell_type=args.install_completion,
            completion_location=args.completion_location
        )
        return # Exit after installing completion script

    if args.list:
        logger.debug("Selected to only list results, rather than"
            " update profiles and tokens")

    ##### Process arguments for filtering accounts and roles to authorize #####
    if args.account:
        logger.debug("Selected to filter by account with the"
        " following values: {0}".format(args.account))

    if args.accountalias:
        logger.debug("Selected to filter by account alias with the"
        " following values: {0}".format(args.accountalias))

    if args.rolename:
        logger.debug("Selected to filter by role containing the"
        " following {0}".format(args.rolename))

    if args.profilename:
        logger.debug("Selected to filter by profile name with the"
        " following value: {0}".format(args.profilename))
    ###########################################################################

    if args.sort_display:
        logger.debug("Sort the display output by the following columns: {0}".format(args.sort_display))

    if args.split_display:
        logger.debug("Split the display output by the following columns: {0}".format(args.split_display))

    if args.cookiejar:
        cookiejar_filename = args.cookiejar
    else:
        env_default = "{0}/.aws-federated-auth.cookies".format(expanduser("~"))
        cookiejar_filename = os.getenv("COOKIEJAR", env_default)
    logger.debug("cookiejar_filename: {0}".format(cookiejar_filename))

    ###########################################################################
    # Speed up features
    ###########################################################################
    if args.quick:
        args.update_max_duration = 'none'
        args.skip_alias_check = True
        logger.debug("Quick mode selected, skipping max duration and account alias checks to speed up authentication.")

    ###########################################################################

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
        config_dir_path = expanduser(os.path.dirname(awsconfigfile))
        os.makedirs(config_dir_path, mode=0o700, exist_ok=True)
        os.chmod(config_dir_path, 0o700) # Guarantee final permissions

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

    if keyring is not None and not args.storepass:
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
        # Start timer after password is entered.
        if args.timer:
            start_time = time.time()

        ###########################################################################################
        # Credentials file pre-processing
        ########################################################################################### 
        if not args.resetawsconfigfile:
            # Read in any existing credentials to allow filtering and speed up auth
            try:
                config = configparser.ConfigParser(interpolation=None)
                config.read(awsconfigfile)
            except configparser.Error as e:
                logger.error(f"Error parsing config file {awsconfigfile}", exc_info=args.exceptiontrace)
                print("Current credentials file is corrupted or has invalid format. To continue, you must reset the credentials file to clear out the corrupted data.")
                print(f"This will erase the existing credentials file located at {awsconfigfile}.")
                print("Would you like to reset the credentials file? (y/n): ", end="")
                reset_credentials_file_input = input().lower()
                if reset_credentials_file_input == 'y':
                    logger.debug("User selected to reset credentials file.")
                    args.resetawsconfigfile = True
                else:
                    print("Exiting without authenticating.")
                    return
            
            # Create dict of current config file to aid in filtering and optimizing authentication
            current_config_by_account_number = {}
            for section in config.sections():
                if (current_account_number := config.get(section, 'account_number', fallback=None)) is not None:
                    current_config_by_account_number.setdefault(
                        current_account_number,
                        {
                            'roles':{},
                            'account_alias': config.get(section, 'account_alias', fallback=None),
                        }
                    )
                    if (current_role_name := config.get(section, 'role_name', fallback=None)) is not None:
                        current_config_by_account_number[current_account_number]['roles'][current_role_name] = {
                            'max_duration': int(config.get(section, 'max_duration', fallback=shib.constants.MaxDurationSeconds.DEFAULT.value))
                        }
                    if current_config_by_account_number[current_account_number]['account_alias'] is None:
                        config.get(section, 'account_alias', fallback=None)
        if args.resetawsconfigfile: # Seperate if statement because args.resetawsconfigfile can be set above to True
            current_config_by_account_number = {}
            with open(os.open(awsconfigfile, os.O_CREAT|os.O_WRONLY|os.O_TRUNC, 0o600), "w") as configfile:
                pass # Truncate
            config = configparser.ConfigParser(interpolation=None) # Re-initialize config to empty after truncating file
            config.read(awsconfigfile)

        ###########################################################################################
        # End credentials file pre-processing
        ###########################################################################################

        # Create an instance of the ECPShib class to handle authentication and token retrieval
        from shib import awsshib
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
            sort_display=args.sort_display,
            split_display=args.split_display,
            current_config_by_account_number=current_config_by_account_number,
            update_max_duration=args.update_max_duration,
            update_account_alias=args.update_account_alias,
            max_duration_limit=args.max_duration_limit,
            exceptiontrace=args.exceptiontrace
        )

        # Process filters for authorization
        auth_args = []
        role_name_arg = {'role_name': args.rolename} if args.rolename else {}

        if args.profilename: # Filter by specific profile
            for profilename in args.profilename:
                try:
                    auth_args.append({
                        'account_number': config.get(profilename, 'account_number'),
                        'role_name': config.get(profilename, 'role_name')
                    })
                except (configparser.NoSectionError, configparser.NoOptionError):
                    logger.error(f"The profile {profilename} you are trying to filter by does not exist in your"
                    " aws credentials file. You must have previously authenticated in the past"
                    " to filter by a specific profile name.")
                    
        if args.accountalias: # Filter by specific account alias
            for accountalias in args.accountalias:
                try:
                    accountalias_found = False
                    for section in config.sections():
                        if section.startswith(accountalias + "-"):
                            if config.get(section, 'account_alias', fallback=None) == accountalias:
                                auth_args.append({
                                    'account_number': config.get(section, 'account_number'),
                                    **role_name_arg
                                })
                                accountalias_found = True
                                break
                    if not accountalias_found:
                        logger.error(f"The account alias {accountalias} you are trying to filter by does not exist in your"
                        " aws credentials file. You must have previously authenticated in the past"
                        " to filter by a specific account alias.")
                except (StopIteration, configparser.NoSectionError, configparser.NoOptionError):
                    logger.error(f"The account alias {accountalias} you are trying to filter by does not exist in your"
                    " aws credentials file. You must have previously authenticated in the past"
                    " to filter by a specific account alias.")
                
        if args.account:
            for account in args.account:
                auth_args.append({
                    'account_number': account,
                    **role_name_arg
                })
                
        if not auth_args: # Catch all if no account filters provided
            auth_args.append({**role_name_arg})

        # Authenticate
        for auth_arg in auth_args:
            try:
                AWSCreds.authorize(**auth_arg)
            except ValueError:
                print("Unable to parse SAML assertions - this is probably because your password is incorrect or you failed to "
                        "approve your Duo request")
                if password_stored and keyring is not None:
                    keyring.delete_password("aws-federated-auth", "password")
        
    # Report time taken for script to run if --timer option selected
    if args.timer:
        end_time = time.time()
        duration = end_time - start_time
        min, sec = divmod(duration, 60)
        print(f"Total time to authenticate: {int(min)}m {sec:.2f}s.")


if __name__ == "__main__":
    main()
