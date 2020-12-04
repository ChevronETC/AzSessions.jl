# Examples

```julia
using AzSessions

# VM identity authentication
session = AzSession(;protocol=AzVMCredentials)
t = token(session)

# Client credentials authentication
session = AzSession(;protocol=AzClientCredentials, client_id="myclientid", client_secret="xxxxxxxxxxxxxxx")
t = token(session)

# Device code  flow authentication
session = AzSession()
t = token(session)

# ...or...
session = AzSession(;protocol=AzDeviceCodeFlowCredentials)
t = token(session)

# Authorization code flow authentication
session = AzSession(;protocol=AzAuthCodeFlowCredentials)
t = token(session)
```