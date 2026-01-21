module AWSCS3

include("libaws_c_s3.jl")
using .Libaws_c_s3

include("Util/Util.jl")
using .Util

include("S3/S3.jl")

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

export S3Object, S3ListResult, S3CopyResult

export S3Exception,
    S3Error,
    S3AccessDeniedError,
    S3BucketAlreadyExistsError,
    S3BucketNotFoundError,
    S3BucketNotEmptyError,
    S3ObjectNotFoundError,
    S3InvalidRequestError,
    S3ServerError,
    S3ConnectionError,
    S3AuthenticationError

end
