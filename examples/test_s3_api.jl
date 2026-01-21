using AWSCS3

#___

cfg = S3Config(;
    host = "s3.dev.teteam.work",
    region = "us-east-1",
    access_key = ENV["S3_ACCESS_KEY"],
    secret_key = ENV["S3_SECRET_KEY"]
)

client = s3_client(cfg)

create_bucket(client, "sdk-test-jl1", ignore_existing=true)
create_bucket(client, "sdk-test-jl2", ignore_existing=true)
put_object(client, "sdk-test-jl1", "demo/1mb.bin", rand(UInt8, 1_000_000))
get_object(client, "sdk-test-jl1", "demo/1mb.bin")
copy_object(client, "sdk-test-jl1", "demo/1mb.bin", "sdk-test-jl2", "demo/1mb-copy.bin")

close(client)
