# AzSessions

Authentication for Azure Cloud using Active Directory (OAuth2).  At
present, this package supports 1) VM credentials, 2) client
credentials, 3) authorization code flow and 4) device code flow.

## Setup

AzSessions keeps state in the `~/.azsessions` folder .  In particular,
it 1) uses `~/.azsession/sessions.json` to store OAuth2
tokens, and 2) uses `~/.azsession/manifest.json` to store
information specific to your Azure account.

Use AzSessions to create the `manifest.json` file:
```julia
AzSessions.write_manifest(;client_id="myclientid", client_secret="myclientsecret", tenant="mytenant")
```
or in the case that you do not have access to the `client_secret`:
```julia
AzSessions.write_manifest(;client_id="myclientid", tenant="mytenant")
```
Once the `manifest.json` file exists, AzSessions will use its values as defaults.
For example, when using client credentials to authenticate, AzSessions will use
the `client_id`, `client_secret` and `tenant`  in `manifest.json`.  On the other hand,
when using the authorization code flow or the device code flow, AzSessions will use
the `client_id` and the `tenant` but will not use the `client_secret`.The later is
especially useful if you are working in an environment where your adminstrator does not
share the `client_secret` with the users.

Note that the manifest can also be used to store your preferred protocal.  For example:
```julia
AzSessions.write_manifest(;client_id="myclientid", client_secret="mycientsecret", tenant="mytenant", protocal=AzClientCredentials)
```