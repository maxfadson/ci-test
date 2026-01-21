export S3Client,
    s3_client,
    S3Config,
    bucket_exists,
    list_buckets,
    list_objects,
    list_objects_detailed,
    get_object,
    put_object,
    copy_object,
    delete_object,
    create_bucket,
    delete_bucket,
    set_bucket_versioning,
    object_exists,
    shutdown!

include("client.jl")
include("requests.jl")
include("operations.jl")
include("parser.jl")
