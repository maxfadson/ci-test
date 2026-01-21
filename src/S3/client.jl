using .Util: byte_cursor, assert_nonnull
include("runtime.jl")
const EMPTY_CURSOR = ByteCursor(0, Ptr{UInt8}(C_NULL))

"""
    S3Config

Configuration for creating an S3 client.

# Fields
- `host::String` - S3 endpoint hostname
- `region::String` - AWS region
- `access_key::String` - Access key ID
- `secret_key::String` - Secret access key
- `user_agent::String` - User agent string (default: "AWSCS3.jl")
- `connect_timeout_ms::Int` - Connection timeout in ms (default: 3000)
"""
Base.@kwdef struct S3Config
    host::String
    region::String
    access_key::String
    secret_key::String
    user_agent::String = "AWSCS3.jl"
    connect_timeout_ms::Int = 3000
end

function redact_secret(s::String)::String
    isempty(s) ? "" : "***"
end

function redact_secret_bytes(bytes::Vector{UInt8})::String
    isempty(bytes) ? "" : "***"
end

function Base.show(io::IO, c::S3Config)
    print(io, "S3Config(",
          "host=", repr(c.host),
          ", region=", repr(c.region),
          ", access_key=", repr(redact_secret(c.access_key)),
          ", secret_key=", repr(redact_secret(c.secret_key)),
          ", user_agent=", repr(c.user_agent),
          ", connect_timeout_ms=", c.connect_timeout_ms,
          ")")
end

struct ClientKeepalive
    region_bytes::Vector{UInt8}
    access_key_bytes::Vector{UInt8}
    secret_key_bytes::Vector{UInt8}
    user_agent_bytes::Vector{UInt8}
end

"""
    S3Client

S3 client for AWS S3-compatible storage.

Create with keyword arguments:
```julia
client = S3Client(; host="s3.amazonaws.com", region="us-east-1",
                   access_key="...", secret_key="...")
```

Or from config:
```julia
client = S3Client(S3Config(...))
client = S3Client("path/to/config.json")
```

Close with `shutdown!(client)` or `close(client)`.
"""
mutable struct S3Client
    host::String
    alloc::Ptr{Libaws_c_s3.aws_allocator}
    client::Ptr{Libaws_c_s3.aws_s3_client}
    signing_cfg::Ref{Libaws_c_s3.aws_signing_config_aws}
    signing_cfg_ptr::Ptr{Libaws_c_s3.aws_signing_config_aws}
    endpoint_ptr::Ptr{Libaws_c_s3.aws_uri}
    bootstrap::Ptr{Libaws_c_s3.aws_client_bootstrap}
    resolver::Ptr{aws_host_resolver}
    elg::Ptr{aws_event_loop_group}
    creds::Ptr{Libaws_c_s3.aws_credentials_provider}
    client_cfg::Ref{Libaws_c_s3.aws_s3_client_config}
    keepalive::ClientKeepalive
    closed::Bool
end

function Base.show(io::IO, c::S3Client)
    region = String(c.keepalive.region_bytes)
    user_agent = String(c.keepalive.user_agent_bytes)
    connect_timeout_ms = Int(c.client_cfg[].connect_timeout_ms)
    print(io, "S3Client(",
          "host=", repr(c.host),
          ", region=", repr(region),
          ", user_agent=", repr(user_agent),
          ", connect_timeout_ms=", connect_timeout_ms,
          ", access_key=", repr(redact_secret_bytes(c.keepalive.access_key_bytes)),
          ", secret_key=", repr(redact_secret_bytes(c.keepalive.secret_key_bytes)),
          ", open=", !c.closed,
          ")")
end

function Base.show(io::IO, ::MIME"text/plain", c::S3Client)
    get(io, :compact, false) && return show(io, c)
    region = String(c.keepalive.region_bytes)
    user_agent = String(c.keepalive.user_agent_bytes)
    connect_timeout_ms = Int(c.client_cfg[].connect_timeout_ms)
    print(io, "S3Client\n",
          "  host: ", repr(c.host), "\n",
          "  region: ", repr(region), "\n",
          "  user_agent: ", repr(user_agent), "\n",
          "  connect_timeout_ms: ", connect_timeout_ms, "\n",
          "  access_key: ", repr(redact_secret_bytes(c.keepalive.access_key_bytes)), "\n",
          "  secret_key: ", repr(redact_secret_bytes(c.keepalive.secret_key_bytes)), "\n",
          "  status: ", c.closed ? "closed" : "open")
end



function create_client_config(region_cur::ByteCursor, bootstrap, signing_cfg_ptr, 
                              connect_timeout_ms::Int)::Ref{Libaws_c_s3.aws_s3_client_config}
    connect_timeout_ms < 0 && throw(ArgumentError("connect_timeout_ms must be non-negative"))
    return Ref(Libaws_c_s3.aws_s3_client_config(
        UInt32(64), region_cur, bootstrap, Libaws_c_s3.AWS_MR_TLS_ENABLED,
        Ptr{Libaws_c_s3.aws_tls_connection_options}(C_NULL),
        Ptr{Libaws_c_s3.aws_s3_file_io_options}(C_NULL),
        signing_cfg_ptr, UInt64(0), UInt64(0), UInt64(0), 10.0, UInt64(2_147_483_648),
        Ptr{Libaws_c_s3.aws_retry_strategy}(C_NULL),
        Libaws_c_s3.AWS_MR_CONTENT_MD5_DISABLED,
        Ptr{Libaws_c_s3.aws_s3_client_shutdown_complete_callback_fn}(C_NULL),
        Ptr{Cvoid}(C_NULL),
        Ptr{Libaws_c_s3.aws_http_proxy_options}(C_NULL),
        Ptr{Libaws_c_s3.proxy_env_var_settings}(C_NULL),
        UInt32(connect_timeout_ms),
        Ptr{Libaws_c_s3.aws_s3_tcp_keep_alive_options}(C_NULL),
        Ptr{Libaws_c_s3.aws_http_connection_monitoring_options}(C_NULL),
        false, Csize_t(0), false,
        Ptr{Libaws_c_s3.aws_s3express_provider_factory_fn}(C_NULL),
        Ptr{Cvoid}(C_NULL),
        Ptr{Libaws_c_s3.aws_byte_cursor}(C_NULL),
        Csize_t(0),
        Ptr{Libaws_c_s3.aws_s3_buffer_pool_factory_fn}(C_NULL),
        Ptr{Cvoid}(C_NULL),
    ))
end

function validate_host(host::String)::Nothing
    isempty(host) && throw(ArgumentError("host must not be empty"))
    occursin("://", host) && throw(ArgumentError(
        "host must be a hostname without a scheme (example: \"s3.example.com\"); got $(repr(host))"
    ))
    (occursin('/', host) || occursin('?', host) || occursin('#', host)) && throw(ArgumentError(
        "host must not include path, query, or fragment; got $(repr(host))"
    ))
    return nothing
end

function S3Client(; alloc::AllocPtr=default_allocator(), host::String, region::String,
                  access_key::String, secret_key::String,
                  user_agent::String="AWSCS3.jl",
                  connect_timeout_ms::Int=3000)::S3Client
    validate_host(host)
    runtime_attached = false
    elg = Ptr{aws_event_loop_group}(C_NULL)
    resolver = Ptr{aws_host_resolver}(C_NULL)
    bootstrap = Ptr{Libaws_c_s3.aws_client_bootstrap}(C_NULL)
    creds = Ptr{Libaws_c_s3.aws_credentials_provider}(C_NULL)
    client = Ptr{Libaws_c_s3.aws_s3_client}(C_NULL)

    try
        alloc = ensure_runtime!(alloc)
        runtime_attached = true

        elg = assert_nonnull(event_loop_group_new(alloc), "aws_event_loop_group_new_default")
        resolver_opts = Ref(aws_host_resolver_default_options(32, elg, C_NULL, C_NULL))
        resolver = assert_nonnull(host_resolver_new_default(alloc, resolver_opts), "aws_host_resolver_new_default")
        bootstrap_opts = Ref(aws_client_bootstrap_options(elg, resolver, C_NULL, C_NULL, C_NULL))
        bootstrap = assert_nonnull(client_bootstrap_new(alloc, bootstrap_opts), "aws_client_bootstrap_new")

        access_key_bytes = Vector{UInt8}(codeunits(access_key))
        secret_key_bytes = Vector{UInt8}(codeunits(secret_key))
        creds_opts = Ref(aws_credentials_provider_static_options(
            Libaws_c_s3.aws_credentials_provider_shutdown_options(Ptr{Cvoid}(C_NULL), Ptr{Cvoid}(C_NULL)),
            byte_cursor(access_key_bytes), byte_cursor(secret_key_bytes), EMPTY_CURSOR, EMPTY_CURSOR,
        ))
        creds = GC.@preserve access_key_bytes secret_key_bytes creds_opts begin
            credentials_provider_new_static(alloc, creds_opts)
        end
        assert_nonnull(creds, "aws_credentials_provider_new_static")

        region_bytes = Vector{UInt8}(codeunits(region))
        region_cur = byte_cursor(region_bytes)
        signing_cfg = Ref{Libaws_c_s3.aws_signing_config_aws}(
            Libaws_c_s3.aws_signing_config_aws(ntuple(_ -> UInt8(0), 256))
        )
        GC.@preserve region_bytes signing_cfg begin
            Libaws_c_s3.aws_s3_init_default_signing_config(signing_cfg, region_cur, creds)
        end
        signing_cfg_ptr = Base.unsafe_convert(Ptr{Libaws_c_s3.aws_signing_config_aws}, signing_cfg)

        client_cfg = create_client_config(region_cur, bootstrap, signing_cfg_ptr, connect_timeout_ms)
        client = GC.@preserve access_key_bytes secret_key_bytes signing_cfg client_cfg begin
            Libaws_c_s3.aws_s3_client_new(alloc, client_cfg)
        end
        assert_nonnull(client, "aws_s3_client_new")

        user_agent_bytes = Vector{UInt8}(codeunits(user_agent))
        keepalive = ClientKeepalive(region_bytes, access_key_bytes, secret_key_bytes, user_agent_bytes)
        endpoint_ptr = Ptr{Libaws_c_s3.aws_uri}(C_NULL)

        return S3Client(host, alloc, client, signing_cfg, signing_cfg_ptr, endpoint_ptr,
                        bootstrap, resolver, elg, creds, client_cfg, keepalive, false)
    catch err
        client != C_NULL && Libaws_c_s3.aws_s3_client_release(client)
        creds != C_NULL && credentials_provider_release(creds)
        bootstrap != C_NULL && client_bootstrap_release(bootstrap)
        resolver != C_NULL && host_resolver_release(resolver)
        elg != C_NULL && event_loop_group_release(elg)
        runtime_attached && shutdown_runtime!()
        rethrow(err)
    end
end

S3Client(cfg::S3Config; alloc::AllocPtr=default_allocator())::S3Client =
    S3Client(; alloc, host=cfg.host, region=cfg.region, access_key=cfg.access_key,
             secret_key=cfg.secret_key, user_agent=cfg.user_agent,
             connect_timeout_ms=cfg.connect_timeout_ms)

S3Client(path::String; alloc::AllocPtr=default_allocator())::S3Client =
    S3Client(load_s3_config(path); alloc)

const s3_client = S3Client

"""
    isopen(client::S3Client) -> Bool

Check if client is still open (not yet shut down).
"""
Base.isopen(client::S3Client)::Bool = !client.closed

function shutdown!(client::S3Client)::Nothing
    client.closed && return nothing
    client.closed = true
    
    if client.client != C_NULL
        Libaws_c_s3.aws_s3_client_release(client.client)
        client.client = Ptr{Libaws_c_s3.aws_s3_client}(C_NULL)
    end
    if client.creds != C_NULL
        credentials_provider_release(client.creds)
        client.creds = Ptr{Libaws_c_s3.aws_credentials_provider}(C_NULL)
    end
    if client.bootstrap != C_NULL
        client_bootstrap_release(client.bootstrap)
        client.bootstrap = Ptr{Libaws_c_s3.aws_client_bootstrap}(C_NULL)
    end
    if client.resolver != C_NULL
        host_resolver_release(client.resolver)
        client.resolver = Ptr{aws_host_resolver}(C_NULL)
    end
    if client.elg != C_NULL
        event_loop_group_release(client.elg)
        client.elg = Ptr{aws_event_loop_group}(C_NULL)
    end
    if client.alloc != Ptr{Libaws_c_s3.aws_allocator}(C_NULL)
        shutdown_runtime!()
        client.alloc = Ptr{Libaws_c_s3.aws_allocator}(C_NULL)
    end
    return nothing
end

"""
    close(client::S3Client) -> Nothing

Release all resources held by the client.
"""
Base.close(client::S3Client)::Nothing = shutdown!(client)

function (::Type{S3Client})(f::Function; alloc::AllocPtr=default_allocator(), kwargs...)
    client = S3Client(; alloc, kwargs...)
    try
        return f(client)
    finally
        shutdown!(client)
    end
end

(::Type{S3Client})(f::Function, cfg::S3Config; alloc::AllocPtr=default_allocator()) =
    S3Client(f; alloc, host=cfg.host, region=cfg.region, access_key=cfg.access_key,
             secret_key=cfg.secret_key, user_agent=cfg.user_agent,
             connect_timeout_ms=cfg.connect_timeout_ms)

(::Type{S3Client})(f::Function, path::String; alloc::AllocPtr=default_allocator()) =
    S3Client(f, load_s3_config(path); alloc)
