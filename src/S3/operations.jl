using .Util: s3_path, to_bytes, build_query_string, build_list_params, set_header!, has_header

"""
    S3Object

S3 object metadata returned by list operations.

# Fields
- `key::String` - Object key
- `size::Int` - Object size in bytes
- `last_modified::String` - Last modification timestamp
- `etag::String` - Entity tag
"""
struct S3Object
    key::String
    size::Int
    last_modified::String
    etag::String
end

"""
    S3ListResult

Result from `list_objects_detailed` with pagination info.

# Fields
- `objects::Vector{S3Object}` - Listed objects
- `common_prefixes::Vector{String}` - Common prefixes (for delimiter queries)
- `is_truncated::Bool` - Whether more results are available
- `continuation_token::Union{Nothing,String}` - Token for next page
"""
struct S3ListResult
    objects::Vector{S3Object}
    common_prefixes::Vector{String}
    is_truncated::Bool
    continuation_token::Union{Nothing,String}
end

"""
    S3CopyResult

Result from `copy_object`.

# Fields
- `etag::String` - Entity tag of copied object
- `last_modified::String` - Last modification timestamp
"""
struct S3CopyResult
    etag::String
    last_modified::String
end

"""
    create_bucket(client, bucket; ignore_existing=false) -> Nothing

Create a bucket. If `ignore_existing=true`, succeeds even if bucket exists.
"""
function create_bucket(client::S3Client, bucket::String; ignore_existing::Bool=false)::Nothing
    ok_status = ignore_existing ? (200, 204, 409) : (200, 204)
    execute_request(client; path=s3_path(bucket), method="PUT",
                         meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                         operation="CreateBucket", ok_status=ok_status, bucket=bucket)
    return nothing
end

"""
    delete_bucket(client, bucket; force=false) -> Nothing

Delete a bucket. If `force=true`, deletes all objects first.
"""
function delete_bucket(client::S3Client, bucket::String; force::Bool=false)::Nothing
    force && delete_all_objects!(client, bucket)
    execute_request(client; path=s3_path(bucket), method="DELETE",
                         meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                         operation="DeleteBucket", ok_status=(204, 200), bucket=bucket)
    return nothing
end

function delete_all_objects!(client::S3Client, bucket::String)::Nothing
    for obj in list_objects(client, bucket)
        delete_object(client, bucket, obj.key)
    end
    return nothing
end

"""
    bucket_exists(client, bucket) -> Bool

Check if a bucket exists.
"""
function bucket_exists(client::S3Client, bucket::String)::Bool
    response = execute_request(client; path=s3_path(bucket), method="HEAD",
                                    meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                                    operation="BucketExists", ok_status=(200, 301, 302, 307, 404),
                                    bucket=bucket)
    return response.status != 404
end

"""
    list_buckets(client) -> Vector{String}

List all buckets.
"""
function list_buckets(client::S3Client)::Vector{String}
    response = execute_request(client; path="/", method="GET",
                                    meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                                    operation="ListBuckets", ok_status=(200,))
    return parse_bucket_names(response.body)
end

"""
    set_bucket_versioning(client, bucket; enabled=true) -> Nothing

Enable or suspend versioning for a bucket.
"""
function set_bucket_versioning(client::S3Client, bucket::String; enabled::Bool=true)::Nothing
    status_str = enabled ? "Enabled" : "Suspended"
    body = """<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>$(status_str)</Status></VersioningConfiguration>"""
    body_bytes = Vector{UInt8}(codeunits(body))
    execute_request(client; path=s3_path(bucket) * "?versioning", method="PUT",
                         meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                         operation="PutBucketVersioning", body=body_bytes,
                         headers=["content-type" => "application/xml"],
                         ok_status=(200, 204), bucket=bucket)
    return nothing
end

"""
    put_object(client, bucket, key, body; headers=[], metadata=[]) -> Nothing

Upload an object.
"""
function put_object(client::S3Client, bucket::String, key::String, body::String;
                    headers::Vector{Pair{String,String}}=Pair{String,String}[],
                    metadata::Vector{Pair{String,String}}=Pair{String,String}[])::Nothing
    return put_object(client, bucket, key, to_bytes(body); headers=headers, metadata=metadata)
end

function put_object(client::S3Client, bucket::String, key::String, body::Vector{UInt8};
                    headers::Vector{Pair{String,String}}=Pair{String,String}[],
                    metadata::Vector{Pair{String,String}}=Pair{String,String}[])::Nothing
    hdrs = copy(headers)
    for (k, v) in metadata
        set_header!(hdrs, "x-amz-meta-$(lowercase(k))", v)
    end
    execute_request(client; path=s3_path(bucket, key), method="PUT",
                         meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_PUT_OBJECT,
                         operation="PutObject", body=body, headers=hdrs, 
                         ok_status=(200,), bucket=bucket, key=key)
    return nothing
end

"""
    get_object(client, bucket, key) -> Vector{UInt8}

Download an object.
"""
function get_object(client::S3Client, bucket::String, key::String)::Vector{UInt8}
    response = execute_request(client; path=s3_path(bucket, key), method="GET",
                                    meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                                    operation="GetObject", ok_status=(200,),
                                    body_sink=Vector{UInt8}(undef, 1024*1024), 
                                    bucket=bucket, key=key)
    return response.body
end

"""
    delete_object(client, bucket, key; version_id=nothing) -> Nothing

Delete an object.
"""
function delete_object(client::S3Client, bucket::String, key::String;
                       version_id::Union{Nothing,String}=nothing)::Nothing
    path = s3_path(bucket, key)
    version_id !== nothing && (path *= "?versionId=$(version_id)")
    execute_request(client; path=path, method="DELETE",
                         meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                         operation="DeleteObject", ok_status=(204, 200), 
                         bucket=bucket, key=key)
    return nothing
end

"""
    copy_object(client, src_bucket, src_key, dest_bucket, dest_key; ...) -> S3CopyResult

Copy an object.
"""
function copy_object(client::S3Client, src_bucket::String, src_key::String,
                     dest_bucket::String, dest_key::String;
                     src_version_id::Union{Nothing,String}=nothing,
                     headers::Vector{Pair{String,String}}=Pair{String,String}[],
                     metadata::Vector{Pair{String,String}}=Pair{String,String}[])::S3CopyResult
    copy_source = s3_path(src_bucket, src_key)
    src_version_id !== nothing && (copy_source *= "?versionId=$(src_version_id)")
    
    hdrs = copy(headers)
    for (k, v) in metadata
        set_header!(hdrs, "x-amz-meta-$(lowercase(k))", v)
    end
    if (!isempty(metadata) || any(startswith(k, "x-amz-meta-") for (k, _) in hdrs)) &&
       !has_header(hdrs, "x-amz-metadata-directive")
        set_header!(hdrs, "x-amz-metadata-directive", "REPLACE")
    end
    set_header!(hdrs, "x-amz-copy-source", copy_source)

    response = execute_request(client; path=s3_path(dest_bucket, dest_key), method="PUT",
                                    meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                                    operation="CopyObject", headers=hdrs,
                                    ok_status=(200, 201), bucket=src_bucket, key=src_key)
    return parse_copy_result(response.body)
end

"""
    object_exists(client, bucket, key) -> Bool

Check if an object exists.
"""
function object_exists(client::S3Client, bucket::String, key::String)::Bool
    response = execute_request(client; path=s3_path(bucket, key), method="HEAD",
                                    meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                                    operation="HeadObject", ok_status=(200, 404), 
                                    bucket=bucket, key=key)
    return response.status == 200
end

"""
    list_objects(client, bucket; prefix="", delimiter="", max_keys=nothing, continuation_token="") -> Vector{S3Object}

List objects in a bucket.
"""
function list_objects(client::S3Client, bucket::String;
                      prefix::String="", delimiter::String="", continuation_token::String="",
                      max_keys::Union{Nothing,Int}=nothing)::Vector{S3Object}
    params = build_list_params(; prefix=prefix, delimiter=delimiter, 
                               continuation_token=continuation_token, max_keys=max_keys)
    path = s3_path(bucket) * build_query_string(params)
    response = execute_request(client; path=path, method="GET",
                                    meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                                    operation="ListObjectsV2", ok_status=(200,), bucket=bucket)
    return parse_list_objects(response.body)
end

"""
    list_objects_detailed(client, bucket; ...) -> S3ListResult

List objects with pagination info.
"""
function list_objects_detailed(client::S3Client, bucket::String;
                               prefix::String="", delimiter::String="", continuation_token::String="",
                               max_keys::Union{Nothing,Int}=nothing)::S3ListResult
    params = build_list_params(; prefix=prefix, delimiter=delimiter, 
                               continuation_token=continuation_token, max_keys=max_keys)
    path = s3_path(bucket) * build_query_string(params)
    response = execute_request(client; path=path, method="GET",
                                    meta_type=Libaws_c_s3.AWS_S3_META_REQUEST_TYPE_DEFAULT,
                                    operation="ListObjectsV2", ok_status=(200,), bucket=bucket)
    return parse_list_objects_detailed(response.body)
end
