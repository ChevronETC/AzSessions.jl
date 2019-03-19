# Examples

```julia
using AzSessions

# VM identity authentication
session = AzSession(;protocal=AzVMCredentials)
t = token(session)

# Client credentials authentication
session = AzSession(;protocal=AzClientCredentials, client_id="myclientid", client_secret="xxxxxxxxxxxxxxx")
t = token(session)

# Device code  flow authentication
session = AzSession()
t = token(session)

# ...or...
session = AzSession(;protocal=AzDeviceCodeFlowCredentials)
t = token(session)

# Authorization code flow authentication
session = AzSession(;protocal=AzAuthCodeFlowCredentials)
t = token(session)
```