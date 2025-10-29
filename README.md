# aws-federated-auth

## Description

Script for enumerating and generating authentication profiles 
for roles with federated trust configured in AWS accounts.

You need to have an Identity Provider with support for ECP configured.
The identity provider needs to assert values that string match to AWS role names.

The AWS accounts need to have the Identity Provider configured.
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html

The roles in question need to have trust settings for the Identity Provider configured.
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp.html

## Installation

```console

pip install aws-federated-auth 

```

## Example

Get script help

```console

aws-federated-auth --help

```

Display all authorized accounts

```console

aws-federated-auth --list

```

Display and generate profiles for all authorized accounts

```console

aws-federated-auth

```

Display and generate profiles for specific AWS account

```console

aws-federated-auth --account 123456789

```

Display and generate profile for specific AWS account and specifiy session duration

```console

aws-federated-auth --duration 1200

```

## Using as AWS credential_process

Configure in `~/.aws/config`:

```ini
[profile my-profile]
credential_process = aws-federated-auth --credential-process --account <account-number> --rolename <role-name> --user <username>
```

## Create binary version
Included is a sample spec file for generating a single file distribution.
If your use case isn't one that works with pip installs you can repackage to meet your needs.

```console

pyinstaller aws-federated-auth.spec

```

### Authors/Credits

jdenk@upenn.edu

Based on components of:
    get-aws-creds creds written by batzel@upenn.edu January 10, 2018
