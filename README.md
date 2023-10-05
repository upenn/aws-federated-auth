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

pip install git+ssh://git@github.com/upenn/aws-federated-auth.git 

## Example

Get script help

```python

aws-federated-auth --help

```

Display all authorized accounts

```python

aws-federated-auth --list

```

Display and generate profiles for all authorized accounts

```python

aws-federated-auth

```

Display and generate profiles for specific AWS account

```python

aws-federated-auth --account 123456789

```

Display and generate profile for specific AWS account and specifiy session duration

```python

aws-federated-auth --duration 1200

```

## Create binary version
Included is a sample spec file for generating a single file distribution.
If your use case isn't one that works with pip installs you can repackage to meet your needs.

```python

pyinstaller aws-federated-auth.spec

```

### Authors/Credits

jdenk@upenn.edu

Based on components of:
    get-aws-creds creds written by batzel@upenn.edu January 10, 2018
