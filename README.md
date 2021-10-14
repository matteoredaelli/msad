# msAD


msad is a library and command line tool for working with an Active Directory / LDAP server. It can be used for:
- search objects (users, groups, computers,..)
- search group members
- add/remove members to/from AD groups using DN or sAMaccoutName
- change AD passwords
- check if a user is disabled or locked, group membership

## Install

```bash
pip install msad
```

## Usage

I find useful to add an alias in my ~/.bash_aliases

```bash
alias msad='/usr/local/bin/msad --host=dmc448-01it.group.pirelli.com --port=636 --search_base dc=group,dc=pirelli,dc=com'
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

## License

Copyright © 2021 Matteo Redaelli

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
