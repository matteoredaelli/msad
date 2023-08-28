# msAD


msad is a library and command line tool for working with an Active Directory / LDAP server. It can be used for:
- search objects (users, groups, computers,..)
- search group members
- add/remove members to/from AD groups using DN or sAMaccoutName
- change AD passwords
- check if a user is disabled or locked, group membership


## Usage

```bash
msad --help
```

```text
 COMMAND is one of the following:

     add_member
       Adds the user to a group (using DN or sAMAccountName)

     change_password

     check_user
       Get some info about a user: is it locked? disabled? password expired?

     group_flat_members
       Extract all the (nested) members of a group

     group_member
       Check if the user is a member of a group (using DN or sAMAccountName)

     group_members
       Extract the direct members of a group

     has_expired_password
       Check is user has the expired password

     has_never_expires_password
       Check if a user has never expires password

     is_disabled
       Check if a user is disabled

     is_locked
       Check if the user is locked

     remove_member
       Remove the user from a group (using DN or sAMAccountName)

     search

     user_groups
       Extract the list of groups of a user (using DN or sAMAccountName)

     users
       Find users inside AD. The filter can be the cn or userPrincipalName or samaccoutnname or mail to be searched. Can contain *

```

## Sample

I find useful to add an alias in my ~/.bash_aliases

```bash
alias msad='/usr/local/bin/msad --host=dmc1it.group.redaelli.org --port=636 --search_base dc=group,dc=redaelli,dc=org'
```

Retreive info about a user

```bash
msad check_user matteo 90 \[qliksense_analyzer,qliksense_professional\] 2>/dev/null
```

```json
{"is_disabled": false}
{"is_locked": false}
{"has_never_expires_password": false}
{"has_expired_password": false}
{"membership_qliksense_analyzer": false}
{"membership_qliksense_professional": true}
```

Getting nested group members (it is a pages search, it can retreive more than 1000 users)

```bash
msad --out_format csv --attributes samaccountname,mail,sn,givenName group_flat_members "dc=group,dc=redaelli,dc=org" --group_name "qliksense_admin"
```


## License

Copyright © 2021 2022 Matteo Redaelli

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
