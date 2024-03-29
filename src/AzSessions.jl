module AzSessions

using Base64, Dates, HTTP, JSON, JSONWebTokens, Logging, MbedTLS, Sockets

function logerror(e, loglevel=Logging.Info)
    io = IOBuffer()
    showerror(io, e)
    write(io, "\n\terror type: $(typeof(e))\n")

    local my_current_exceptions
    if VERSION < v"1.7"
        my_current_exceptions = Base.catch_backtrace
    else
        my_current_exceptions = current_exceptions
    end

    for (exc, bt) in my_current_exceptions()
        showerror(io, exc, bt)
        println(io)
    end
    @logmsg loglevel String(take!(io))
    close(io)
end

const _manifest = Dict("client_id"=>"", "client_secret"=>"", "tenant"=>"", "protocol"=>"")

manifestpath() = joinpath(homedir(), ".azsessions")
manifestfile() = joinpath(manifestpath(), "manifest.json")

# allow for the correct spelling of "protocol" and a common mis-spelling ("protocal")
function spelling_mistake(protocol::AbstractString, protocal::AbstractString)
    if protocol == "" && protocal != ""
        protocol = protocal
    end
    protocol
end

function spelling_mistake(protocol, protocal)
    if protocol === nothing && protocal !== nothing
        protocol = protocal
    end
    protocol
end

"""
    AzSessions.write_manifest(;client_id="", client_secret="", tenant="", protocol="")

Write an AzSessions manifest file (~/.azsessions/manifest.json).  The
manifest file contains account specific credentials.

# Notes

## client secret
The client can be configured such that the `client_secret` is not
required for the authorization-code-flow and device-code-flow.  In this
scenario, one may choose to omit setting the `client_secret` in the manifest.
For example:
```julia
AzSessions.write_manifest(;client_id="myclientid", tenant="mytenant")
```

## protocol
The protocol is one of "AzAuthCodeFlowCredentials", "AzDeviceCodeFlowCredentials", "AzClientCredentials"
and "AzVMCredentials".  If the default `protocol=""` is chosen for the manifest, then `AzSession()` will
default to `AzDeviceCodeFlowCredentials`.  The protocol in the manifest can always be over-ridden using
the `protocol` argument to `AzSession`.
"""
function write_manifest(;client_id="", client_secret = "", tenant="", protocol="", protocal="")
    manifest = Dict("client_id"=>client_id, "client_secret"=>client_secret, "tenant"=>tenant, "protocol"=>spelling_mistake(string(protocal), string(protocol)))
    try
        isdir(manifestpath()) || mkdir(manifestpath(); mode=0o700)
        write(manifestfile(), json(manifest, 1))
        chmod(manifestfile(), 0o600)
    catch e
        @error "Failed to write manifest file, $(AzSessions.manifestfile())"
        throw(e)
    end
end

function load_manifest()
    if isfile(manifestfile())
        try
            manifest = JSON.parse(read(manifestfile(), String))
            for key in keys(_manifest)
                _manifest[key] = get(manifest, key, "")
            end
        catch e
            @error "Manifest file ($(AzSessions.manifestfile())) is not valid JSON"
            throw(e)
        end
    else
        @error "Manifest file ($(AzSessions.manifestfile())) does not exist.  Use AzSessions.write_manifest to generate a manifest file."
    end
end

#
# retry logic
#
function isretryable(e::HTTP.Exceptions.StatusError, s)
    e.status == 404 && (return true,s)
    e.status >= 500 && (return true,s)

    if e.status == 429
        for header in e.response.headers
            if lowercase(header[1]) == "retry-after"
                s = parse(Int, header[2]) + rand()
                return true,s
            end
        end
    end

    if e.status == 400
        b = JSON.parse(String(e.response.body))
        if first(get(b, "error_codes", [])) == 50196 # server encountered a client request loop
            @warn "received client request loop error code [50196]."
            s = rand(120:180) # chosen emperically
            return true,s
        end
    end

    false,s
end
isretryable(e::Base.IOError, s) = true,s
isretryable(e::HTTP.Exceptions.ConnectError, s) = true,s
isretryable(e::HTTP.Exceptions.RequestError, s) = true,s
isretryable(e::HTTP.Exceptions.TimeoutError, s) = true,s
isretryable(e::MbedTLS.MbedException, s) = true,s
isretryable(e::Base.EOFError, s) = true,s
isretryable(e::Sockets.DNSError, s) = true,s
isretryable(e, s) = false,s

function retrywarn(i, s, e)
    @warn "retry $i, sleeping for $s seconds"
    logerror(e, Logging.Warn)
end

macro retry(retries, ex::Expr)
    quote
        local r
        for i = 1:($(esc(retries))+1)
            try
                r = $(esc(ex))
                break
            catch e
                maximum_backoff = 60
                s = min(2.0^(i-1), maximum_backoff) + rand()
                _isretryable,s = isretryable(e, s)
                (i < $(esc(retries)) && _isretryable) || throw(e)
                retrywarn(i, s, e)
                sleep(s)
            end
        end
        r
    end
end

abstract type AzSessionAbstract end

"""
    token(session[; offset=Second(rand(300:600))])

Return the OAuth2 token associate with `session`.  The `offset` ensures
that the token is valid for at least `offset` time.  The default offset
is randomized between 5 and 15 minutes.  We randomize the offset to avoid
calling the Azure authentication end-point at the same time from many
VMs operating in parallel.
"""
function token end

"""
    scrub!(session)

Remove sensitive information from `session` (e.g. token, client secret)
"""
function scrub! end

#
# Client credentials
#
struct AzClientCredentials end
mutable struct AzClientCredentialsSession <: AzSessionAbstract
    protocol::String
    client_id::String
    client_secret::String
    expiry::DateTime
    resource::String
    tenant::String
    token::String
end
function AzClientCredentialsSession(;
        client_id = _manifest["client_id"],
        client_secret = _manifest["client_secret"],
        resource = "https://management.azure.com/",
        tenant = _manifest["tenant"])
    client_secret == "" && error("AzClientCredentials requires client_secret, but got client_secret=\"\"")
    AzClientCredentialsSession(string(AzClientCredentials), client_id, client_secret, now(Dates.UTC), resource, tenant, "")
end
function AzClientCredentialsSession(d::Dict)
    AzClientCredentialsSession(
        spelling_mistake(get(d, "protocol", ""), get(d, "protocal", "")),
        d["client_id"],
        d["client_secret"],
        DateTime(d["expiry"]),
        d["resource"],
        d["tenant"],
        d["token"])
end

function Base.copy(session::AzClientCredentialsSession)
    AzClientCredentialsSession(
        session.protocol,
        session.client_id,
        session.client_secret,
        session.expiry,
        session.resource,
        session.tenant,
        session.token)
end

unqualify_protocol_string(protocol) = replace(protocol, "AzSessions."=>"")

function samesession(session1::AzClientCredentialsSession, session2::AzClientCredentialsSession)
    unqualify_protocol_string(session1.protocol) == unqualify_protocol_string(session2.protocol) &&
        session1.client_id == session2.client_id &&
        session1.client_secret == session2.client_secret &&
        session1.resource == session2.resource &&
        session1.tenant == session2.tenant
end

function token(session::AzClientCredentialsSession; offset=Second(rand(300:600)))
    session.token != "" && now(Dates.UTC) < (session.expiry - offset) && return session.token

    r = @retry 10 HTTP.request(
        "POST",
        "https://login.microsoft.com/$(session.tenant)/oauth2/token",
        ["Content-Type" => "application/x-www-form-urlencoded"],
        "grant_type=client_credentials&client_id=$(session.client_id)&client_secret=$(HTTP.escapeuri(session.client_secret))&resource=$(HTTP.escapeuri(session.resource))",
        retry = false)

    rbody = JSON.parse(String(r.body))
    session.token = rbody["access_token"]
    session.expiry = now(Dates.UTC) + Dates.Second(rbody["expires_in"])

    session.token
end

function scrub!(session::AzClientCredentialsSession)
    session.token = ""
    session.client_secret = ""
    session
end

Base.show(io::IO, session::AzClientCredentialsSession) = write(io, "Azure client credentials session")

#
# VirtualMachine credentials
#
struct AzVMCredentials end
mutable struct AzVMSession <: AzSessionAbstract
    protocol::String
    expiry::DateTime
    resource::String
    token::String
end
function AzVMSession(;resource = "https://management.azure.com/")
    AzVMSession(string(AzVMCredentials), now(Dates.UTC), resource, "")
end
function AzVMSession(d::Dict)
    AzVMSession(
        spelling_mistake(get(d, "protocol", ""), get(d, "protocal", "")),
        DateTime(d["expiry"]),
        d["resource"],
        d["token"])
end

function Base.copy(session::AzVMSession)
    AzVMSession(
        session.protocol,
        session.expiry,
        session.resource,
        session.token)
end

function samesession(session1::AzVMSession, session2::AzVMSession)
    unqualify_protocol_string(session1.protocol) == unqualify_protocol_string(session2.protocol) && session1.resource == session2.resource
end

function token(session::AzVMSession; offset=Second(rand(300:600)))
    session.token != "" && now(Dates.UTC) < (session.expiry - offset) && return session.token

    r = @retry 10 HTTP.request(
        "GET",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$(session.resource)",
        ["Metadata"=>"true"],
        retry = false)

    rbody = JSON.parse(String(r.body))
    session.token = rbody["access_token"]
    session.expiry = now(Dates.UTC) + Dates.Second(rbody["expires_in"])

    session.token
end

function scrub!(session::AzVMSession)
    session.token = ""
    session
end

Base.show(io::IO, session::AzVMSession) = write(io, "Azure virtual machine credentials session")

function mergescopes(scope1, scope2)
    scopes1 = split(scope1, (' ', '+'))
    scopes2 = split(scope2, (' ', '+'))
    join(union(scopes1, scopes2), '+')
end

#
# Authorization code flow credentials
#
struct AzAuthCodeFlowCredentials end
mutable struct AzAuthCodeFlowSession <: AzSessionAbstract
    protocol::String
    client_id::String
    expiry::DateTime
    id_token::String
    lock::Bool
    redirect_uri::String
    refresh_token::String
    scope::String
    scope_auth::String
    tenant::String
    token::String
end
function AzAuthCodeFlowSession(;
        client_id = _manifest["client_id"],
        redirect_uri = "http://localhost:44300/reply",
        scope = "openid+offline_access+https://management.azure.com/user_impersonation",
        scope_auth = "openid+offline_access+https://management.azure.com/user_impersonation+https://storage.azure.com/user_impersonation",
        tenant = _manifest["tenant"])
    AzAuthCodeFlowSession(string(AzAuthCodeFlowCredentials), client_id, now(Dates.UTC), "", false, redirect_uri, "", scope, mergescopes(scope, scope_auth), tenant, "")
end
function AzAuthCodeFlowSession(d::Dict)
    AzAuthCodeFlowSession(
        spelling_mistake(get(d, "protocol", ""), get(d, "protocal", "")),
        d["client_id"],
        DateTime(d["expiry"]),
        d["id_token"],
        d["lock"],
        d["redirect_uri"],
        d["refresh_token"],
        d["scope"],
        d["scope_auth"],
        d["tenant"],
        d["token"])
end

function AzSession(session::AzAuthCodeFlowSession; scope="", lazy=false)
    scope == "" && (scope = session.scope)
    _session = AzAuthCodeFlowSession(
        session.protocol,
        session.client_id,
        session.expiry,
        session.id_token,
        session.lock,
        session.redirect_uri,
        session.refresh_token,
        scope,
        session.scope_auth,
        session.tenant,
        session.token)
    lazy || token(_session)
    _session
end

function Base.copy(session::AzAuthCodeFlowSession)
    AzAuthCodeFlowSession(
        session.protocol,
        session.client_id,
        session.expiry,
        session.id_token,
        session.lock,
        session.redirect_uri,
        session.refresh_token,
        session.scope,
        session.scope_auth,
        session.tenant,
        session.token)
end

function samesession(session1::AzAuthCodeFlowSession, session2::AzAuthCodeFlowSession)
    unqualify_protocol_string(session1.protocol) == unqualify_protocol_string(session2.protocol) &&
        session1.client_id == session2.client_id &&
        session1.redirect_uri == session2.redirect_uri &&
        samescope(session1.scope, session2.scope) &&
        samescope(session1.scope_auth, session2.scope_auth) &&
        session1.tenant == session2.tenant
end

session_has_tokens(session::AzAuthCodeFlowSession) = session.token != "" && session.refresh_token != ""

function update_session_from_cached_session!(session::AzAuthCodeFlowSession, cached_session::AzAuthCodeFlowSession)
    session.expiry = cached_session.expiry
    session.id_token = cached_session.id_token
    session.refresh_token = cached_session.refresh_token
    session.token = cached_session.token
end

function audience_from_token(token)
    local audience
    try
        decodedJWT = JSONWebTokens.decode(JSONWebTokens.None(), token)
        audience = get(decodedJWT, "aud", "")
    catch
        @warn "Unable to retrieve audience from token."
        audience = ""
    end
    audience
end

function audience_from_scope(scope)
    scopes = split(scope, ('+',' '))
    i = findfirst(_scope->startswith(_scope, "https://"), scopes)
    "https://"*split(replace(scopes[i], "https://"=>""), '/')[1]
end

function _token(session::AzAuthCodeFlowSession, bootstrap=false; offset=Second(rand(300:600)))
    while session.lock
        sleep(1)
    end
    session.lock = true

    # use the existing token:
    if session.token != "" && now(Dates.UTC) < (session.expiry - offset) && audience_from_token(session.token) == audience_from_scope(session.scope)
        session.lock = false
        return session.token
    end

    # use the refresh token to get a new token:
    if session.refresh_token != "" && refresh_token(session)
        session.lock = false
        return session.token
    end

    if bootstrap_token_from_cache!(session, bootstrap; offset)
        session.lock = false
        return ""
    end

    # otherwise, user is required to authenticate:
    port = parse(Int, parse(HTTP.URI, session.redirect_uri).port)
    state = rand(Int)
    auth_code = ""

    @debug "starting server..."
    local server
    try
        server = Sockets.listen(Sockets.localhost, port)
    catch
        error("AzSessions: there is already a server listening on port $port")
    end
    with_logger(NullLogger()) do
        tsk = @async HTTP.serve(Sockets.localhost, port; server=server) do request::HTTP.Request
            queries = split(parse(HTTP.URI, request.target).query, '&')
            for query in queries
                q = split(query, '=')
                if q[1] == "code"
                    auth_code = q[2]
                    break
                end
            end
            HTTP.Response(200, "Logged in via AzSessions.jl")
        end
    end

    authcode_uri = "https://login.microsoft.com/$(session.tenant)/oauth2/v2.0/authorize?client_id=$(session.client_id)&response_type=code&redirect_uri=$(session.redirect_uri)&response_mode=query&scope=$(session.scope_auth)&state=$state&prompt=select_account"

    exitcode = 1
    if Sys.iswindows()
        cmd = get(ENV, "COMSPEC", "cmd")
        _authcode_uri = replace(authcode_uri, "&"=>"^&")
        c = open(`$cmd /c start $_authcode_uri`)
        wait(c)
        exitcode = c.exitcode
    elseif Sys.islinux()
        c = open(`gio open $authcode_uri`)
        wait(c)
        exitcode = c.exitcode
    end

    if exitcode != 0
        @info "Failed to open browser. To authenticate, please open the following url on the local machine:\n\t$authcode_uri"
    end

    while auth_code == ""
        sleep(1)
    end
    close(server)

    token_uri = "https://login.microsoftonline.com/$(session.tenant)/oauth2/v2.0/token"
    token_body = "client_id=$(session.client_id)&scope=$(session.scope)&code=$auth_code&redirect_uri=$(session.redirect_uri)&grant_type=authorization_code"

    @debug "trading auth code for token..."
    r = @retry 10 HTTP.request(
        "POST",
        token_uri,
        ["Content-Type"=>"application/x-www-form-urlencoded"],
        token_body;
        retry = false)

    rbody = JSON.parse(String(r.body))
    session.token = rbody["access_token"]
    session.id_token = get(rbody, "id_token", "") # only exists if openid is used in the scope
    session.refresh_token = get(rbody, "refresh_token", "") # online exists if offline_access is used in the scope
    session.expiry = now(Dates.UTC) + Dates.Second(rbody["expires_in"])

    session_has_tokens(session) && record_session(session)
    session.token
end

function scrub!(session::AzAuthCodeFlowSession)
    session.token = ""
    session.id_token = ""
    session.refresh_token = ""
    session
end

Base.show(io::IO, session::AzAuthCodeFlowSession) = write(io, "Azure authorization code flow session")

#
# Device code flow credentials
#
struct AzDeviceCodeFlowCredentials end
mutable struct AzDeviceCodeFlowSession <: AzSessionAbstract
    protocol::String
    client_id::String
    expiry::DateTime
    id_token::String
    lock::Bool
    refresh_token::String
    scope::String
    scope_auth::String
    tenant::String
    token::String
end
function AzDeviceCodeFlowSession(;
        client_id = _manifest["client_id"],
        scope = "openid+offline_access+https://management.azure.com/user_impersonation",
        scope_auth = "openid+offline_access+https://management.azure.com/user_impersonation+https://storage.azure.com/user_impersonation",
        tenant = _manifest["tenant"])
    AzDeviceCodeFlowSession(string(AzDeviceCodeFlowCredentials), client_id, now(Dates.UTC), "", false, "", scope, mergescopes(scope, scope_auth), tenant, "")
end
function AzDeviceCodeFlowSession(d::Dict)
    AzDeviceCodeFlowSession(
        spelling_mistake(get(d, "protocol", ""), get(d, "protocal", "")),
        d["client_id"],
        DateTime(d["expiry"]),
        d["id_token"],
        d["lock"],
        d["refresh_token"],
        d["scope"],
        d["scope_auth"],
        d["tenant"],
        d["token"])
end

function AzSession(session::AzDeviceCodeFlowSession; scope="", lazy=false)
    scope == "" && (scope = session.scope)
    _session = AzDeviceCodeFlowSession(
        session.protocol,
        session.client_id,
        session.expiry,
        session.id_token,
        session.lock,
        session.refresh_token,
        scope,
        session.scope_auth,
        session.tenant,
        session.token)
    lazy || token(_session)
    _session
end

function Base.copy(session::AzDeviceCodeFlowSession)
    AzDeviceCodeFlowSession(
        session.protocol,
        session.client_id,
        session.expiry,
        session.id_token,
        session.lock,
        session.refresh_token,
        session.scope,
        session.scope_auth,
        session.tenant,
        session.token)
end

function samesession(session1::AzDeviceCodeFlowSession, session2::AzDeviceCodeFlowSession)
    unqualify_protocol_string(session1.protocol) == unqualify_protocol_string(session2.protocol) &&
        session1.client_id == session2.client_id &&
        samescope(session1.scope, session2.scope) &&
        session1.tenant == session2.tenant
end

session_has_tokens(session::AzDeviceCodeFlowSession) = session.token != "" && session.refresh_token != ""

function update_session_from_cached_session!(session::AzDeviceCodeFlowSession, cached_session::AzDeviceCodeFlowSession)
    session.expiry = cached_session.expiry
    session.id_token = cached_session.id_token
    session.refresh_token = cached_session.refresh_token
    session.token = cached_session.token
end

function _token(session::AzDeviceCodeFlowSession, bootstrap=false; offset=Second(rand(300:600)))
    while session.lock
        sleep(1)
    end
    session.lock = true

    # use the existing token:
    if session.token != "" && now(Dates.UTC) < (session.expiry - offset) && audience_from_scope(session.scope) == audience_from_token(session.token)
        session.lock = false
        return session.token
    end

    # use the refresh token to get a new token:
    if session.refresh_token != "" && refresh_token(session)
        session.lock = false
        return session.token
    end

    if bootstrap_token_from_cache!(session, bootstrap; offset)
        session.lock = false
        return session.token
    end

    _r = @retry 1 HTTP.request(
        "POST",
        "https://login.microsoft.com/$(session.tenant)/oauth2/v2.0/devicecode",
        ["Content-Type"=>"application/x-www-form-urlencoded"],
        "client_id=$(session.client_id)&scope=$(session.scope)")
    r = JSON.parse(String(_r.body))

    device_code = r["device_code"]

    @info r["message"]
    flush(stdout)
    flush(stderr)

    local _r
    while true
        _r = @retry 1 HTTP.request(
            "POST",
            "https://login.microsoft.com/$(session.tenant)/oauth2/v2.0/token",
            ["Content-Type"=>"application/x-www-form-urlencoded"],
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=$(session.client_id)&device_code=$device_code";
            status_exception = false,
            retry = false)

        _r.status == 200 && break

        __r = String(_r.body)
        r = JSON.parse(__r)
        if r["error"] == "authorization_pending"
            sleep(5)
        else
            error(__r)
        end
    end

    r = JSON.parse(String(_r.body))

    session.id_token = get(r, "id_token", "") # only exists if openid is used in scope
    session.refresh_token = get(r, "refresh_token", "") # only exists if offline_access is used in scope
    session.token = r["access_token"]
    session.expiry = now(Dates.UTC) + Dates.Second(r["expires_in"])

    session_has_tokens(session) && record_session(session)
    session.token
end

function refresh_token(session::Union{AzAuthCodeFlowSession, AzDeviceCodeFlowSession})
    resource = audience_from_scope(session.scope)
    body = "client_id=$(session.client_id)&refresh_token=$(session.refresh_token)&grant_type=refresh_token&scope=$(session.scope)&resource=$resource"

    r = @retry 10 HTTP.request(
        "POST",
        "https://login.microsoftonline.com/$(session.tenant)/oauth2/token",
        ["Content-Type"=>"application/x-www-form-urlencoded"],
        body;
        retry = false)

    rbody = JSON.parse(String(r.body))

    local status
    if haskey(rbody, "error")
        status = false
    else
        status = true
        session.token = rbody["access_token"]
        session.refresh_token = rbody["refresh_token"]
        session.expiry = now(Dates.UTC) + Dates.Second(rbody["expires_in"])
    end
    status
end

function scrub!(session::AzDeviceCodeFlowSession)
    session.token = ""
    session.id_token = ""
    session.refresh_token = ""
    session
end

Base.show(io::IO, session::AzDeviceCodeFlowSession) = write(io, "Azure device code flow credentials session")

function AzCredentials(protocol::AbstractString)
    protocols = Dict("AzClientCredentials"=>AzClientCredentials, "AzDeviceCodeCredentials"=>AzDeviceCodeFlowCredentials, "AzAuthCodeFlowCredentials"=>AzAuthCodeFlowCredentials, "AzVMCredentials"=>AzVMCredentials, ""=>nothing)
    if !haskey(protocols, protocol)
        error("Authentication protocol, $protocol, is not recognized.")
    end
    protocols[protocol]
end

#
# Recording sessions to disk
#
sessionpath() = joinpath(homedir(), ".azsessions")
sessionfile() = joinpath(sessionpath(), "sessions.json")

function bootstrap_token_from_cache!(session, bootstrap; offset)
    cached_session, session_is_recorded = get_recorded_session(session)
    if session_is_recorded
        if bootstrap == false
            update_session_from_cached_session!(session, cached_session)
            session.lock = false
            token(session, true; offset)
            return true
        else
            @warn "failed to use cached token, token cache may be corrupted."
        end
    end
    false
end

unqualify_json_sessions(json_sessions) = replace(json_sessions, "AzSessions."=>"")

function recorded_sessions()
    local rsessions
    if isfile(sessionfile())
        rsessions = JSON.parse(unqualify_json_sessions(read(sessionfile(), String)))
    else
        rsessions = Dict("sessions"=>[])
    end
    rsessions
end

function write_sessions(rsessions)
    rm(sessionfile(); force=true)
    write(sessionfile(), unqualify_json_sessions(json(rsessions)))
    chmod(sessionfile(), 0o400)
end

function record_session(session)
    if !isdir(sessionpath())
        try
            mkdir(sessionpath(); mode=0o700)
        catch
            @warn "unable to make directory $(sessionpath()): will not record sessions"
            return
        end
    end

    rsessions = recorded_sessions()
    has_session = false
    for (i,rsession) in enumerate(rsessions)
        if samesession(session, rsession)
            rsessions[i] = json(session)
            has_session = true
        end
    end
    if !has_session
        pushfirst!(rsessions["sessions"], json(session))
    end
    write_sessions(rsessions)
end

samesession(session1, session2) = false

function samescope(scope1, scope2)
    scopes1 = split(scope1, '+')
    scopes2 = split(scope2, '+')

    if length(scopes1) != length(scopes2)
        return false
    else
        for _scope1 in scopes1
            if _scope1 ∉ scopes2
                return false
            end
        end
    end
    true
end

function get_recorded_session(session)
    rsessions = recorded_sessions()
    for json_recorded_session in rsessions["sessions"]
        recorded_session = AzSession(json_recorded_session)
        if samesession(session, recorded_session)
            return recorded_session, true
        end
    end
    session, false
end

function delete_session(session)
    rsessions = recorded_sessions()
    i = 0
    for (isession, json_recorded_session) in enumerate(rsessions["sessions"])
        recorded_session = AzSession(json_recorded_session)
        if samesession(session, recorded_session)
            i = isession
            break
        end
    end
    if i > 0
        deleteat!(rsessions["sessions"], i)
    end
    write_sessions(rsessions)
end

function token(session::Union{AzAuthCodeFlowSession, AzDeviceCodeFlowSession}, bootstrap=false; offset=Second(rand(300:600)))
    try
        _token(session, bootstrap; offset)
    finally
        session.lock = false
    end
end

#
# API
#
"""
    session = AzSession([; kwargs...])

Create an Azure session for authentication using a specific authentication
protocol.  The available protocols and their `kwargs` are as follows.

## Authorization code flow
```julia
session = AzSession(;
    protocol = _manifest["protocol"] | AzDeviceCodeFlowCredentials,
    client_id = AzSessions._manifest["client_id"],
    redirect_uri = "http://localhost:44300/reply",
    scope = "openid+offline_access+https://storage.azure.com/user_impersonation",
    scope_auth = "openid+offline_access+https://management.azure.com/user_impersonation+https://storage.azure.com/user_impersonation",
    tenant = AzSessions._manifest["tenant"],
    lazy = false,
    clearcache = false)
```

## Device code flow
```julia
session = AzSession(;
    protocol = AzDeviceCodeCredentials
    client_id = AzSessions._manifest["client_id"],
    scope = "openid+offline_access+https://management.azure.com/user_impersonation",
    scope_auth = "openid+offline_access+https://management.azure.com/user_impersonation+https://storage.azure.com/user_impersonation",
    tenant = AzSessions._manifest["tenant"],
    clearcache = false)
```

## Client Credentials
```julia
session = AzSession(;
    protocol = AzClientCredentials,
    tenant=AzSessions._manifest["tenant"],
    client_id=AzSessions._manifest["client_id"],
    client_secret=AzSessions._manifest["client_secret"],
    resource="https://management.azure.com/",
    clearcache = false)
```

## VM Credentials
```julia
session = AzSession(;
    protocol = AzVMCredentials,
    resource = "https://management.azure.com/",
    clearcache = false)
```

## New audience
Create a session from an existing auth code flow session or device code flow session,
but with a new scope.  This means that we can get a session with a new audience without
requiring re-authentication.  Note that the new scope must be in `session.scope_auth`.

```julia
session = AzSession(;
    protocol=AzAuthCodeFlowCredentials,
    scope_auth="openid+offline_access+https://management.azure.com/user_impersonation+https://storage.azure.com/user_impersonation",
    scope="openid+offline_access+https://management.azure.com/user_impersonation")

t = token(session) # token for `https://management.azure.com` audience
session = AzSession(session; scope="openid+offline_access+https://storage.azure.com/user_impersonation")
t = token(session) # token for `https://storage.azure.com` audience without needing to re-authenticate
```
# Notes
* If `lazy=false`, then authenticate at the time of construction.  Otherwise, wait until the first use of the session before authenticating.
* If `clearcache=false`, then check the session-cache for an existing token rather than re-authenticating.  The cache is stored in a JSON file (`~/.azsessions/sessions.json`).
* The default protocol can be set in the manifest (see the `AzSessions.write_manifest` method for more information).
"""
function AzSession(; protocol=nothing, protocal=nothing, lazy=false, clearcache=false, kwargs...)
    protocol = spelling_mistake(protocol, protocal)
    load_manifest()
    protocol === nothing && (protocol = AzCredentials(spelling_mistake(get(_manifest, "protocol", ""), get(_manifest, "protocal", ""))))
    protocol === nothing && (protocol = AzDeviceCodeFlowCredentials)

    local session
    if protocol == AzClientCredentials
        session = AzClientCredentialsSession(;kwargs...)
    elseif protocol == AzVMCredentials
        session = AzVMSession(;kwargs...)
    elseif protocol == AzAuthCodeFlowCredentials
        session = AzAuthCodeFlowSession(;kwargs...)
    elseif protocol == AzDeviceCodeFlowCredentials
        session = AzDeviceCodeFlowSession(;kwargs...)
    else
        error("Unknown credentials protocol.")
    end

    clearcache && delete_session(session)
    lazy || token(session)
    session
end

function AzSession(d::Dict)
    protocol = replace(spelling_mistake(get(d, "protocol", ""), get(d, "protocal", "")), "AzSessions."=>"")
    if protocol == "AzClientCredentials"
        AzClientCredentialsSession(d)
    elseif protocol == "AzVMCredentials"
        AzVMSession(d)
    elseif protocol == "AzAuthCodeFlowCredentials"
        AzAuthCodeFlowSession(d)
    elseif protocol == "AzDeviceCodeFlowCredentials"
        AzDeviceCodeFlowSession(d)
    else
        error("Unknown credentials protocol: $protocol.")
    end
end
AzSession(jsonobject::String) = AzSession(JSON.parse(jsonobject))

AzSession(session::AzSessionAbstract) = session

export AzAuthCodeFlowCredentials, AzClientCredentials, AzDeviceCodeFlowCredentials, AzSession, AzSessionAbstract, AzVMCredentials, scrub!, token

end
