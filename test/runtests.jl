using AzSessions, Dates, HTTP, JSON, JSONWebTokens, Test

credentials = JSON.parse(ENV["AZURE_CREDENTIALS"])
AzSessions.write_manifest(;client_id=credentials["clientId"], client_secret=credentials["clientSecret"], tenant=credentials["tenantId"])

function running_on_azure()
    try
        HTTP.request(
            "GET",
            "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
            Dict("Metadata"=>"true"))
        return true
    catch
        return false
    end
end

if running_on_azure()
    # TODO - not sure why this doesn't work on CI
    @test_skip @testset "AzSessions, VM" begin
        session = AzSession(;protocol=AzVMCredentials)
        @test now(Dates.UTC) <= session.expiry
        t = token(session)
        @test isa(t,String)
        t2 = token(session)
        @test t2 == t

        session.token = "x"
        session.expiry = now(Dates.UTC) - Dates.Second(1)
        t2 = token(session)
        @test t2 != "x"
    end
end

@testset "AzSessions, Client Credentials" begin
    session = AzSession(;protocol=AzClientCredentials, client_id=credentials["clientId"], client_secret=credentials["clientSecret"])
    @test now(Dates.UTC) < session.expiry
    t = token(session)
    @test isa(t,String)
    t2 = token(session)
    @test t2 == t

    session.token = "x"
    session.expiry = now(Dates.UTC) - Dates.Second(1)
    t2 = token(session)
    @test t2 != "x"
end

# TODO: requires user interaction (can we use Mocking.jl)
@test_skip @testset "AzSessions, Device code flow credentials" begin
    session = AzSession(;protocol=AzDeviceCodeFlowCredentials)
    @test now(Dates.UTC) <= session.expiry
    t = token(session)
    @test isa(t,String)
    t2 = token(session)
    @test t2 == t

    session.token == "x"
    session.expiry = now(Dates.UTC) - Dates.Second(1)
    t2 = token(session)
    @test t2 != "x"

    session2 = AzSession(session;scope="https://storage.azure.com/user_impersonation")
    t = token(session2)
    decodedJWT = JSONWebTokens.decode(JSONWebTokens.None(), t)
    @test decodedJWT["aud"] == "https://storage.azure.com"
end

# TODO - the following testset will only work if the machine can start a web-browser
@test_skip @testset "AzSessions, Authorization code flow credentials" begin
    session = AzSession(;protocol=AzAuthCodeFlowCredentials)
    @test now(Dates.UTC) <= session.expiry
    t = token(session)
    @test isa(t,String)
    t2 = token(session)
    @test t2 == t

    session.token == "x"
    session.expiry = now(Dates.UTC) - Dates.Second(1)
    t2 = token(session)
    @test t2 != "x"

    session2 = AzSession(session;scope="https://storage.azure.com/user_impersonation")
    t = token(session2)
    decodedJWT = JSONWebTokens.decode(JSONWebTokens.None(), t)
    @test decodedJWT["aud"] == "https://storage.azure.com"
end

# TODO: requires user interaction, can we use Mocking.jl?
@test_skip @testset "AzSessions, Device code flow credentials is the default" begin
    session = AzSession()
    @test now(Dates.UTC) <= session.expiry
    t = token(session)
    @test isa(t,String)
    t2 = token(session)
    @test t2 == t

    session.token == "x"
    session.expiry = now(Dates.UTC) - Dates.Second(1)
    t2 = token(session)
    @test t2 != "x"
end

@testset "AzSessions, Client Credentials, serialize" begin
    session = AzSessions.AzClientCredentialsSession(
        "AzClientCredentials",
        "myclientid",
        "myclientsecret",
        now(),
        "myresource",
        "mytenant",
        "mytoken")

    jsonsession = json(session)
    _session = AzSession(jsonsession)

    @test session.protocol == _session.protocol
    @test session.client_id == _session.client_id
    @test session.client_secret == _session.client_secret
    @test session.expiry == _session.expiry
    @test session.resource == _session.resource
    @test session.tenant == _session.tenant
    @test session.token == _session.token

    _session = AzSession(JSON.parse(jsonsession))
    @test session.protocol == _session.protocol
    @test session.client_id == _session.client_id
    @test session.client_secret == _session.client_secret
    @test session.expiry == _session.expiry
    @test session.resource == _session.resource
    @test session.tenant == _session.tenant
    @test session.token == _session.token
end

@testset "AzSessions, VM Credentials, serialize" begin
    session = AzSessions.AzVMSession(
        "AzVMCredentials",
        now(),
        "myresource",
        "mytoken")

    jsonsession = json(session)
    _session = AzSession(jsonsession)

    @test session.protocol == _session.protocol
    @test session.expiry == _session.expiry
    @test session.resource == _session.resource
    @test session.token == _session.token
end

@testset "AzSessions, Auth Code Credentials, serialize" begin
    session = AzSessions.AzAuthCodeFlowSession(
        "AzAuthCodeFlowCredentials",
        "clientid",
        now(),
        "myidtoken",
        false,
        "redirecturi",
        "refreshtoken",
        "scopeauth",
        "scopetoken",
        "tenant",
        "token")

    jsonsession = json(session)
    _session = AzSession(jsonsession)

    @test session.protocol == _session.protocol
    @test session.client_id == _session.client_id
    @test session.expiry == _session.expiry
    @test session.id_token == _session.id_token
    @test session.lock == _session.lock
    @test session.redirect_uri == _session.redirect_uri
    @test session.refresh_token == _session.refresh_token
    @test session.scope_auth == _session.scope_auth
    @test session.scope == _session.scope
    @test session.tenant == _session.tenant
    @test session.token == _session.token

    _session = AzSession(JSON.parse(jsonsession))

    @test session.protocol == _session.protocol
    @test session.client_id == _session.client_id
    @test session.expiry == _session.expiry
    @test session.id_token == _session.id_token
    @test session.lock == _session.lock
    @test session.redirect_uri == _session.redirect_uri
    @test session.refresh_token == _session.refresh_token
    @test session.scope_auth == _session.scope_auth
    @test session.scope == _session.scope
    @test session.tenant == _session.tenant
    @test session.token == _session.token
end

@testset "AzSessions, Device Code Credentials, serialize" begin
    session = AzSessions.AzDeviceCodeFlowSession(
        "AzDeviceCodeFlowCredentials",
        "myclientid",
        now(),
        "myidtoken",
        true,
        "myrefreshtoken",
        "myscope",
        "myscope_auth",
        "mytenant",
        "mytoken")

    jsonsession = json(session)
    _session = AzSession(jsonsession)

    @test session.protocol == _session.protocol
    @test session.client_id == _session.client_id
    @test session.expiry == _session.expiry
    @test session.id_token == _session.id_token
    @test session.lock == _session.lock
    @test session.refresh_token == _session.refresh_token
    @test session.scope == _session.scope
    @test session.scope_auth == _session.scope_auth
    @test session.tenant == _session.tenant
    @test session.token == _session.token

    _session = AzSession(JSON.parse(jsonsession))

    @test session.protocol == _session.protocol
    @test session.client_id == _session.client_id
    @test session.expiry == _session.expiry
    @test session.id_token == _session.id_token
    @test session.lock == _session.lock
    @test session.refresh_token == _session.refresh_token
    @test session.scope == _session.scope
    @test session.scope_auth == _session.scope_auth
    @test session.tenant == _session.tenant
    @test session.token == _session.token
end

@testset "AzSesions, Client Credentials, copy" begin
    session = AzSessions.AzClientCredentialsSession(
        "AzClientCredentials",
        "myclientid",
        "myclientsecret",
        now(),
        "myresource",
        "mytenant",
        "mytoken")

    _session = copy(session)
    @test session.protocol == _session.protocol
    @test session.client_id == _session.client_id
    @test session.client_secret == _session.client_secret
    @test session.expiry == _session.expiry
    @test session.resource == _session.resource
    @test session.tenant == _session.tenant
    @test session.token == _session.token
end

@testset "AzSessions, VM Credentials, copy" begin
    session = AzSessions.AzVMSession(
        "AzVMCredentials",
        now(),
        "myresource",
        "mytoken")

    _session = copy(session)

    @test session.protocol == _session.protocol
    @test session.expiry == _session.expiry
    @test session.resource == _session.resource
    @test session.token == _session.token
end

@testset "AzSessions, Auth code flow credentials, copy" begin
    session = AzSessions.AzAuthCodeFlowSession(
        "AzAuthCodeFlowCredentials",
        "clientid",
        now(),
        "myidtoken",
        false,
        "redirecturi",
        "refreshtoken",
        "scopeauth",
        "scopetoken",
        "tenant",
        "token")

    _session = copy(session)

    @test session.protocol == _session.protocol
    @test session.client_id == _session.client_id
    @test session.expiry == _session.expiry
    @test session.id_token == _session.id_token
    @test session.lock == _session.lock
    @test session.redirect_uri == _session.redirect_uri
    @test session.refresh_token == _session.refresh_token
    @test session.scope_auth == _session.scope_auth
    @test session.scope == _session.scope
    @test session.tenant == _session.tenant
    @test session.token == _session.token
end

@testset "AzSessions, Device Code Credentials, copy" begin
    session = AzSessions.AzDeviceCodeFlowSession(
        "AzDeviceCodeFlowCredentials",
        "myclientid",
        now(),
        "myidtoken",
        true,
        "myrefreshtoken",
        "myscope",
        "myscope_auth",
        "mytenant",
        "mytoken")

    _session = copy(session)

    @test session.protocol == _session.protocol
    @test session.client_id == _session.client_id
    @test session.expiry == _session.expiry
    @test session.id_token == _session.id_token
    @test session.lock == _session.lock
    @test session.refresh_token == _session.refresh_token
    @test session.scope == _session.scope
    @test session.scope_auth == _session.scope_auth
    @test session.tenant == _session.tenant
    @test session.token == _session.token
end

@testset "AzSessions, merge scopes" begin
    session = AzSession(;
        scope="openid+offline_access+https://management.azure.com/user_impersonation",
        scope_auth = "openid+offline_access+https://storage.azure.com/user_impersonation",
        lazy = true)

    scopes = split(session.scope_auth, '+')
    @test length(scopes) == 4
    @test length(unique(scopes)) == 4
    for scope in scopes
        @test scope  ∈ ["openid","offline_access","https://management.azure.com/user_impersonation","https://storage.azure.com/user_impersonation"]
    end
end

@testset "AzSessions, VM credentials, scrub" begin
    session = AzSessions.AzClientCredentialsSession(
            "AzClientCredentials",
            "myclientid",
            "myclientsecret",
            now(),
            "myresource",
            "mytenant",
            "mytoken")

    scrub!(session)

    @test session.client_secret == ""
    @test session.token == ""
end

@testset "AzSessions, Auth code flow, scrub" begin
    session = AzSessions.AzAuthCodeFlowSession(
        "AzAuthCodeFlowCredentials",
        "clientid",
        now(),
        "myidtoken",
        false,
        "redirecturi",
        "refreshtoken",
        "scopeauth",
        "scopetoken",
        "tenant",
        "token")

    scrub!(session)

    @test session.id_token == ""
    @test session.refresh_token == ""
    @test session.token == ""
end

@testset "AzSessions, Device code flow, scrub" begin
    session = AzSessions.AzDeviceCodeFlowSession(
        "AzDeviceCodeFlowCredentials",
        "myclientid",
        now(),
        "myidtoken",
        true,
        "myrefreshtoken",
        "myscope",
        "myscope_auth",
        "mytenant",
        "mytoken")

    scrub!(session)

    @test session.id_token == ""
    @test session.refresh_token == ""
    @test session.token == ""
end

@testset "AzSessions, write_manifest" begin
    AzSessions.write_manifest(;client_id="myclientid", client_secret="myclientsecret", tenant="mytenant")

    manifest = JSON.parse(read(AzSessions.manifestfile(), String))
    @test manifest["client_id"] == "myclientid"
    @test manifest["client_secret"] == "myclientsecret"
    @test manifest["tenant"] == "mytenant"
end