# htgettoken

`htgettoken` gets OIDC bearer access tokens by interacting with a
Hashicorp vault server configured for retrieving and storing OIDC
refresh tokens using the
[htvault-config package](https://github.com/fermitools/htvault-config).

For details on its usage please see the
[man page](https://htmlpreview.github.io/?https://github.com/fermitools/htgettoken/blob/master/htgettoken.html).

Packaging for Red Hat Enterprise Linux systems is included.  Rpms are
distributed in the
[Open Science Grid yum repositories](https://opensciencegrid.org/docs/common/yum/#install-the-osg-repositories).
After enabling the OSG repositories, do this as root to install it:
```
yum install htgettoken
```

htgettoken and Vault are also integrated with 
[HTCondor](https://htcondor-vault.readthedocs.io/en/latest/admin-manual/setting-up-special-environments.html?highlight=vault#enabling-the-fetching-and-use-of-oauth2-credentials).
It is currently available in htcondor-8.9.13 in the OSG 3.5 
osg-upcoming-development yum repository and the
OSG 3.6 osg-development yum repository.

See this
[paper](https://github.com/fermitools/htgettoken/files/6063416/CHEP21_Paper_Htgettoken.pdf)
submitted to
[vCHEP 2021](https://indico.cern.ch/event/948465/)
for a description of htgettoken, htvault-config, and their HTCondor
integration.
