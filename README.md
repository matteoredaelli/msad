# msAD

*msad* is a library and command line tool for working with an Active Directory / LDAP server from Unix, Linux and MacOs systems.

It supports authentication with user/pwd and kerberos

It supports paginations: it can retreive more than 2000 objects (a limit of AD)

It can be used for:
- search objects (users, groups, computers,..)
- search (recursively) group memberships and all user's groups
- add/remove members to/from AD groups using DN or sAMaccoutName
- change AD passwords
- check if a user is disabled or locked, group membership

## Prerequisites

python >= 3.9

For kerboros auth

  - krb5 lib and tools (like kinit, ...)
  - a keytab file or 
  
## Installation

```bash
pipx install msad
```

## COnfiguration

Create a configuration file in $HOME/.msad.toml as suggested by

```bash
msad get-sample-config
```


## Usage


```bash
msad --help

python -m msad --help

```


For kerberos authentication, first you need to login to AD / get a ticket kerberos with

```bash
kinit youraduser
```



```text
msad search "(samaccountname=matteo)"  --out-format=json

msad search "(cn=redaelli*)" --attribute mail --attribute samaccountname --out-format=json

msad group-members qlik_analyzer_users --nested

msad group-add-member qlik_analyzer_users matteo

msad group-remove-member qlik_analyzer_users matteo

msad user-groups matteo --nested

```

## Sample



## License

Copyright © 2021 - 2025 Matteo Redaelli

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
