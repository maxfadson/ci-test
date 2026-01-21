using .Util: byte_cursor, to_bytes, try_bytes_to_string

"""
    S3Exception <: Exception

Abstract base type for all S3-related exceptions.
"""
abstract type S3Exception <: Exception end

struct S3Error <: S3Exception
    operation::String
    status::Int
    error_code::Int
    code::Union{Nothing,String}
    message::String
    request_id::Union{Nothing,String}
    resource::Union{Nothing,String}
    raw_body::Vector{UInt8}
end

function Base.showerror(io::IO, err::S3Error)
    status_str = err.status > 0 ? " (HTTP $(err.status))" : ""
    code_str = err.code === nothing ? "" : "[$(err.code)] "
    print(io, "S3Error: ", err.operation, " failed", status_str, "\n  ", code_str, err.message)
    err.resource !== nothing && print(io, "\n  Resource: ", err.resource)
    err.request_id !== nothing && print(io, "\n  RequestId: ", err.request_id)
end

struct S3AccessDeniedError <: S3Exception
    operation::String
    resource::String
    message::String
end

function Base.showerror(io::IO, err::S3AccessDeniedError)
    print(io, "S3AccessDeniedError: Access denied for '", err.operation, "' on '", err.resource, "'\n  ", err.message)
end

struct S3BucketAlreadyExistsError <: S3Exception
    bucket::String
end

function Base.showerror(io::IO, err::S3BucketAlreadyExistsError)
    print(io, "S3BucketAlreadyExistsError: Bucket '", err.bucket, "' already exists.")
end

struct S3BucketNotFoundError <: S3Exception
    bucket::String
    operation::String
end

function Base.showerror(io::IO, err::S3BucketNotFoundError)
    print(io, "S3BucketNotFoundError: Bucket '", err.bucket, "' does not exist.")
end

struct S3BucketNotEmptyError <: S3Exception
    bucket::String
end

function Base.showerror(io::IO, err::S3BucketNotEmptyError)
    print(io, "S3BucketNotEmptyError: Bucket '", err.bucket, "' is not empty.")
end

struct S3ObjectNotFoundError <: S3Exception
    bucket::String
    key::String
    operation::String
end

function Base.showerror(io::IO, err::S3ObjectNotFoundError)
    print(io, "S3ObjectNotFoundError: Object '", err.key, "' not found in bucket '", err.bucket, "'.")
end

struct S3InvalidRequestError <: S3Exception
    operation::String
    message::String
end

function Base.showerror(io::IO, err::S3InvalidRequestError)
    print(io, "S3InvalidRequestError: Invalid request for '", err.operation, "'\n  ", err.message)
end

struct S3ServerError <: S3Exception
    operation::String
    status::Int
    message::String
end

function Base.showerror(io::IO, err::S3ServerError)
    print(io, "S3ServerError: Server error (HTTP ", err.status, ") for '", err.operation, "'\n  ", err.message)
end

struct S3ConnectionError <: S3Exception
    host::String
    message::String
end

function Base.showerror(io::IO, err::S3ConnectionError)
    print(io, "S3ConnectionError: Failed to connect to '", err.host, "'\n  ", err.message)
end

struct S3AuthenticationError <: S3Exception
    operation::String
    message::String
end

function Base.showerror(io::IO, err::S3AuthenticationError)
    print(io, "S3AuthenticationError: Authentication failed for '", err.operation, "'\n  ", err.message)
end

const HTTP_STATUS_MESSAGES = Dict{Int,String}(
    400 => "Bad request",
    401 => "Unauthorized",
    403 => "Access denied",
    404 => "Not found",
    405 => "Method not allowed",
    409 => "Conflict",
    412 => "Precondition failed",
    500 => "Internal server error",
    503 => "Service unavailable",
)

const S3_ERROR_CODE_TYPES = Dict{String,Symbol}(
    "AccessDenied" => :access_denied,
    "AccountProblem" => :access_denied,
    "AllAccessDisabled" => :access_denied,
    "BucketAlreadyExists" => :bucket_exists,
    "BucketAlreadyOwnedByYou" => :bucket_exists,
    "BucketNotEmpty" => :bucket_not_empty,
    "NoSuchBucket" => :bucket_not_found,
    "NoSuchKey" => :object_not_found,
    "NoSuchVersion" => :object_not_found,
    "InvalidAccessKeyId" => :auth_error,
    "SignatureDoesNotMatch" => :auth_error,
    "InvalidSecurity" => :auth_error,
    "InvalidBucketName" => :invalid_request,
    "InvalidObjectName" => :invalid_request,
    "InvalidArgument" => :invalid_request,
    "MalformedXML" => :invalid_request,
    "InternalError" => :server_error,
    "ServiceUnavailable" => :server_error,
    "SlowDown" => :server_error,
)

struct S3ErrorResponse
    code::Union{Nothing,String}
    message::Union{Nothing,String}
    request_id::Union{Nothing,String}
    resource::Union{Nothing,String}
    raw_text::String
end

function capture_error_element(pattern::Regex, text::AbstractString)::Union{Nothing,String}
    m = match(pattern, text)
    return m === nothing ? nothing : m.captures[1]
end

function parse_error_response(body::Vector{UInt8})::Union{Nothing,S3ErrorResponse}
    text = try_bytes_to_string(body)
    text === nothing && return nothing

    code = capture_error_element(r"<Code>([^<]+)</Code>", text)
    message = capture_error_element(r"<Message>([^<]+)</Message>", text)
    request_id = capture_error_element(r"<RequestId>([^<]+)</RequestId>", text)
    resource = capture_error_element(r"<Resource>([^<]+)</Resource>", text)

    if code === nothing && message === nothing
        trimmed = strip(text)
        isempty(trimmed) && return nothing
        message = trimmed
    end

    return S3ErrorResponse(code, message, request_id, resource, text)
end

struct S3RequestContext
    operation::String
    bucket::Union{Nothing,String}
    key::Union{Nothing,String}
    host::String
end

S3RequestContext(operation::String, host::String) =
    S3RequestContext(operation, nothing, nothing, host)

S3RequestContext(operation::String, bucket::String, host::String) =
    S3RequestContext(operation, bucket, nothing, host)

struct S3Response
    status::Int
    error_code::Int
    body::Vector{UInt8}
end

function classify_error_type(code::Union{Nothing,String}, status::Int)::Symbol
    if code !== nothing
        err_type = get(S3_ERROR_CODE_TYPES, code, nothing)
        err_type !== nothing && return err_type
    end
    status == 401 && return :auth_error
    status == 403 && return :access_denied
    status == 404 && return :not_found
    status == 409 && return :conflict
    status in (400, 405, 412) && return :invalid_request
    status in (500, 502, 503, 504) && return :server_error
    status == 0 && return :connection_error
    return :unknown
end

function create_error_from_aws_code(ctx::S3RequestContext, aws_error_code::Int)::S3Exception
    message = aws_error_str(aws_error_code)
    aws_error_code != 0 && return S3ConnectionError(ctx.host, message)
    return S3Error(ctx.operation, 0, aws_error_code, nothing, message, nothing, nothing, UInt8[])
end

function create_error_from_response(ctx::S3RequestContext, response::S3Response)::S3Exception
    parsed = parse_error_response(response.body)
    code = parsed !== nothing ? parsed.code : nothing
    message = determine_error_message(parsed, response)
    resource = determine_resource_string(ctx, parsed)
    err_type = classify_error_type(code, response.status)
    return create_typed_error(err_type, ctx, response, message, resource, code, parsed)
end

function determine_error_message(parsed::Union{Nothing,S3ErrorResponse}, response::S3Response)::String
    parsed !== nothing && parsed.message !== nothing && return parsed.message
    status_msg = get(HTTP_STATUS_MESSAGES, response.status, nothing)
    status_msg !== nothing && return status_msg
    response.error_code != 0 && return aws_error_str(response.error_code)
    parsed !== nothing && !isempty(strip(parsed.raw_text)) && return strip(parsed.raw_text)
    return "request_failed"
end

function determine_resource_string(ctx::S3RequestContext, parsed::Union{Nothing,S3ErrorResponse})::String
    parsed !== nothing && parsed.resource !== nothing && return parsed.resource
    ctx.key !== nothing && ctx.bucket !== nothing && return "$(ctx.bucket)/$(ctx.key)"
    ctx.bucket !== nothing && return ctx.bucket
    return "unknown"
end

function create_typed_error(err_type::Symbol, ctx::S3RequestContext, response::S3Response,
                           message::String, resource::String, code::Union{Nothing,String},
                           parsed::Union{Nothing,S3ErrorResponse})::S3Exception
    err_type == :access_denied && return S3AccessDeniedError(ctx.operation, resource, message)
    err_type == :auth_error && return S3AuthenticationError(ctx.operation, message)
    err_type == :bucket_exists && ctx.bucket !== nothing && return S3BucketAlreadyExistsError(ctx.bucket)
    err_type == :bucket_not_empty && ctx.bucket !== nothing && return S3BucketNotEmptyError(ctx.bucket)
    err_type == :bucket_not_found && ctx.bucket !== nothing && return S3BucketNotFoundError(ctx.bucket, ctx.operation)
    err_type == :object_not_found && ctx.bucket !== nothing && ctx.key !== nothing && return S3ObjectNotFoundError(ctx.bucket, ctx.key, ctx.operation)

    if err_type == :not_found
        ctx.key !== nothing && ctx.bucket !== nothing && return S3ObjectNotFoundError(ctx.bucket, ctx.key, ctx.operation)
        ctx.bucket !== nothing && return S3BucketNotFoundError(ctx.bucket, ctx.operation)
    end

    if err_type == :conflict && ctx.bucket !== nothing
        ctx.operation in ("CreateBucket", "PutBucket") && return S3BucketAlreadyExistsError(ctx.bucket)
        ctx.operation in ("DeleteBucket", "RemoveBucket") && return S3BucketNotEmptyError(ctx.bucket)
    end

    err_type == :invalid_request && return S3InvalidRequestError(ctx.operation, message)
    err_type == :server_error && return S3ServerError(ctx.operation, response.status, message)
    err_type == :connection_error && return S3ConnectionError(ctx.host, message)

    request_id = parsed !== nothing ? parsed.request_id : nothing
    parsed_resource = parsed !== nothing ? parsed.resource : nothing
    return S3Error(ctx.operation, response.status, response.error_code, code, message,
                   request_id, parsed_resource, copy(response.body))
end

struct S3Request
    msg::Ptr{Libaws_c_s3.aws_http_message}
    headers::Ptr{Libaws_c_s3.aws_http_headers}
    body_stream::Ptr{Libaws_c_s3.aws_input_stream}
    keepalive::Vector{Vector{UInt8}}
    cursor_refs::Vector{Any}
end

function execute_raw_request(client, signing_cfg_ptr, endpoint_uri_ptr, alloc;
                             request::S3Request, meta_type,
                             ctx::S3RequestContext, body_sink::Vector{UInt8})::S3Response
    op_bytes = Vector{UInt8}(codeunits(ctx.operation))
    opts = Ref(Libaws_c_s3.aws_s3_meta_request_options(
        meta_type, byte_cursor(op_bytes), signing_cfg_ptr, request.msg, EMPTY_CURSOR,
        Libaws_c_s3.AWS_S3_RECV_FILE_CREATE_OR_REPLACE, UInt64(0), false, EMPTY_CURSOR,
        Ptr{Libaws_c_s3.aws_s3_file_io_options}(C_NULL),
        Ptr{Libaws_c_s3.aws_async_input_stream}(C_NULL), false,
        Ptr{Libaws_c_s3.aws_s3_checksum_config}(C_NULL),
        UInt64(0), false, UInt64(0), Ptr{Cvoid}(C_NULL),
        Ptr{Libaws_c_s3.aws_s3_meta_request_headers_callback_fn}(C_NULL),
        Ptr{Libaws_c_s3.aws_s3_meta_request_receive_body_callback_fn}(C_NULL),
        Ptr{Libaws_c_s3.aws_s3_meta_request_receive_body_callback_ex_fn}(C_NULL),
        Ptr{Libaws_c_s3.aws_s3_meta_request_finish_fn}(C_NULL),
        Ptr{Libaws_c_s3.aws_s3_meta_request_shutdown_fn}(C_NULL),
        Ptr{Libaws_c_s3.aws_s3_meta_request_progress_fn}(C_NULL),
        Ptr{Libaws_c_s3.aws_s3_meta_request_telemetry_fn}(C_NULL),
        Ptr{Libaws_c_s3.aws_s3_meta_request_upload_review_fn}(C_NULL),
        endpoint_uri_ptr,
        Ptr{Libaws_c_s3.aws_s3_meta_request_resume_token}(C_NULL),
        Ptr{UInt64}(C_NULL), EMPTY_CURSOR, UInt32(0),
    ))

    res = Ref(S3ShimResult(Libaws_c_s3.aws_byte_buf(0, Ptr{UInt8}(C_NULL), 0, Ptr{Libaws_c_s3.aws_allocator}(C_NULL)), 0, 0))
    keepalive = request.keepalive
    cursor_refs = request.cursor_refs
    code = GC.@preserve op_bytes opts request res keepalive cursor_refs begin
        s3_shim_make_request(alloc, client, opts, res)
    end

    code != 0 && throw(create_error_from_aws_code(ctx, code))

    body = unsafe_wrap(Vector{UInt8}, res[].body.buffer, res[].body.len; own=false)
    body_copy = copy(body)
    s3_shim_result_clean(res)

    return S3Response(res[].status, res[].error_code, body_copy)
end

function execute_request(client::S3Client;
                         path::String, method::String,
                         meta_type::Libaws_c_s3.aws_s3_meta_request_type,
                         operation::String, body::Vector{UInt8}=UInt8[],
                         headers::Vector{Pair{String,String}}=Pair{String,String}[],
                         ok_status::Tuple{Vararg{Int}}=(200,),
                         body_sink::Vector{UInt8}=UInt8[],
                         bucket::Union{Nothing,String}=nothing,
                         key::Union{Nothing,String}=nothing)::S3Response
    !isopen(client) && throw(ArgumentError("S3Client is closed"))
    ctx = S3RequestContext(operation, bucket, key, client.host)
    req = build_s3_request(client.alloc; host=client.host, path=path, method=method,
                           body=body, headers=headers,
                           user_agent_bytes=client.keepalive.user_agent_bytes)
    response = try
        execute_raw_request(client.client, client.signing_cfg_ptr, client.endpoint_ptr, client.alloc;
                            request=req, meta_type=meta_type, ctx=ctx, body_sink=body_sink)
    finally
        release_request!(req)
    end
    !(response.status in ok_status) && throw(create_error_from_response(ctx, response))
    return response
end

function build_s3_request(alloc; host::String, path::String, method::String,
                          body::Vector{UInt8}=UInt8[],
                          headers::Vector{Pair{String,String}}=Pair{String,String}[],
                          user_agent_bytes::Vector{UInt8}=UInt8[])::S3Request
    msg = http_message_new_request(alloc)
    headers_ptr = http_message_get_headers(msg)
    keepalive = Vector{Vector{UInt8}}()
    cursor_refs = Any[]

    method_bytes = Vector{UInt8}(codeunits(method))
    push!(keepalive, method_bytes)
    @assert http_message_set_method(msg, byte_cursor(method_bytes)) == 0

    path_bytes = Vector{UInt8}(codeunits(path))
    push!(keepalive, path_bytes)
    @assert http_message_set_path(msg, byte_cursor(path_bytes)) == 0

    host_bytes = Vector{UInt8}(codeunits(host))
    push!(keepalive, host_bytes)
    @assert http_headers_add(headers_ptr, byte_cursor("Host"), byte_cursor(host_bytes)) == 0

    ua_bytes = isempty(user_agent_bytes) ? Vector{UInt8}(codeunits("AWSCS3.jl")) : user_agent_bytes
    push!(keepalive, ua_bytes)
    @assert http_headers_add(headers_ptr, byte_cursor("User-Agent"), byte_cursor(ua_bytes)) == 0

    for (name, value) in headers
        name_bytes = to_bytes(name)
        value_bytes = to_bytes(value)
        push!(keepalive, name_bytes, value_bytes)
        @assert http_headers_add(headers_ptr, byte_cursor(name_bytes), byte_cursor(value_bytes)) == 0
    end

    body_stream = Ptr{Libaws_c_s3.aws_input_stream}(C_NULL)
    if !isempty(body)
        push!(keepalive, body)
        cursor_ref = Ref(byte_cursor(body))
        push!(cursor_refs, cursor_ref)
        body_stream = input_stream_new_from_cursor(alloc, cursor_ref)
        http_message_set_body_stream(msg, body_stream)
        len_bytes = Vector{UInt8}(codeunits(string(length(body))))
        push!(keepalive, len_bytes)
        @assert http_headers_add(headers_ptr, byte_cursor("Content-Length"), byte_cursor(len_bytes)) == 0
    end

    return S3Request(msg, headers_ptr, body_stream, keepalive, cursor_refs)
end

function release_request!(req::S3Request)::Nothing
    req.body_stream != C_NULL && input_stream_release(req.body_stream)
    http_message_release(req.msg)
    return nothing
end
