using AWSCS3

Base.@kwdef struct S3Config
    host::String
    region::String
    access_key::String
    secret_key::String
    user_agent::String = "LibAWSCS3"
    connect_timeout_ms::Int = 3000
    # ...
end

function Base.show(io::IO, c::S3Config)
    print(io, "S3Config(",
          "host=", repr(c.host),
          ", region=", repr(c.region),
          ", user_agent=", repr(c.user_agent),
          ")")
end

function s3_client(c::S3Config)
    s3_client(; c.host, c.region, c.access_key, c.secret_key)
end

s3_config = S3Config(
    host = "s3.dev.teteam.work",
    region = "us-east-1",
    access_key = ENV["S3_ACCESS_KEY"],
    secret_key = ENV["S3_SECRET_KEY"],
)

client = s3_client(s3_config)

put_object(client, "sdk-test-jl1", "demo/1gb.bin", rand(UInt8, 1_000_000));
get_object(client, "sdk-test-jl1", "demo/1gb.bin")

# close(client)
# listing = list_objects(client, "sdk-test-jl1")
# String(listing) |> println
