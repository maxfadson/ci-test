module Util

using ..Libaws_c_s3: ByteCursor, aws_last_error, aws_error_str
using Printf

export byte_cursor, to_bytes, assert_nonnull
export is_unreserved_byte, encode_uri_path, s3_path
export set_header!, has_header, get_header
export build_query_string, build_list_params
export try_bytes_to_string

function try_bytes_to_string(body::Vector{UInt8})::Union{Nothing,String}
    isempty(body) && return nothing
    try
        return String(copy(body))
    catch
        return nothing
    end
end

byte_cursor(s::String) = ByteCursor(length(codeunits(s)), pointer(codeunits(s)))
byte_cursor(v::Vector{UInt8}) = ByteCursor(length(v), pointer(v))

to_bytes(body::Vector{UInt8}) = body
to_bytes(body::String) = Vector{UInt8}(codeunits(body))

function assert_nonnull(ptr, name::String)
    if ptr == C_NULL
        code = aws_last_error()
        error("$(name) returned NULL: $(code) $(aws_error_str(code))")
    end
    return ptr
end

function is_unreserved_byte(b::UInt8)::Bool
    return (b >= 0x41 && b <= 0x5a) ||
           (b >= 0x61 && b <= 0x7a) ||
           (b >= 0x30 && b <= 0x39) ||
           b in (0x2d, 0x2e, 0x5f, 0x7e)
end

function encode_uri_path(key::String)::String
    buf = IOBuffer()
    for b in codeunits(key)
        if b == 0x2f || is_unreserved_byte(b)
            write(buf, b)
        else
            @printf(buf, "%%%02X", b)
        end
    end
    return String(take!(buf))
end

function s3_path(bucket::String, key::String="")::String
    encoded_key = isempty(key) ? "" : encode_uri_path(key)
    return string("/", bucket, isempty(encoded_key) ? "" : "/", encoded_key)
end

function set_header!(headers::Vector{Pair{String,String}}, name::String, value::String)
    name_lower = lowercase(name)
    for i in eachindex(headers)
        if first(headers[i]) == name_lower
            headers[i] = name_lower => value
            return headers
        end
    end
    push!(headers, name_lower => value)
    return headers
end

function has_header(headers::Vector{Pair{String,String}}, name::String)::Bool
    name_lower = lowercase(name)
    for (k, _) in headers
        k == name_lower && return true
    end
    return false
end

function get_header(headers::Vector{Pair{String,String}}, name::String)::Union{Nothing,String}
    name_lower = lowercase(name)
    for (k, v) in headers
        k == name_lower && return v
    end
    return nothing
end

function build_query_string(params::Vector{Pair{String,String}})::String
    return isempty(params) ? "" : "?" * join((string(k, "=", v) for (k, v) in params), "&")
end

function build_list_params(; prefix::String, delimiter::String,
                            continuation_token::String, max_keys::Union{Nothing,Int})::Vector{Pair{String,String}}
    params = Pair{String,String}["list-type" => "2"]
    !isempty(prefix) && push!(params, "prefix" => prefix)
    !isempty(delimiter) && push!(params, "delimiter" => delimiter)
    !isempty(continuation_token) && push!(params, "continuation-token" => continuation_token)
    max_keys !== nothing && push!(params, "max-keys" => string(max_keys))
    return params
end


end
