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

(Work in progress. `pip install` is not yet ready.)

```console

pip install aws-federated-auth 

```

## Compile Binary

Clone the repo. In your virtual environment, install the following requrements:

```
requests
boto3
keyring
pyinstaller
```

Then, compile using `pyinstaller`.

```console
pyinstaller aws-federated-auth.spec
```

The binary should be located in the `dist` directory.

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

Display and generate profile for specific AWS account and specifiy the maximum allowable duration in seconds for the temporary credentials

```console

aws-federated-auth --max-duration-limit 1200

```

### Authors/Credits

jdenk@upenn.edu

rchu@upenn.edu

hughmac@upenn.edu

Based on components of:
    get-aws-creds creds written by batzel@upenn.edu January 10, 2018
