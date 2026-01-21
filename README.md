# AWSCS3.jl

[![Stable](https://img.shields.io/badge/docs-stable-blue.svg)](https://.github.io/AWSCS3.jl/stable/)
[![Dev](https://img.shields.io/badge/docs-dev-blue.svg)](https://.github.io/AWSCS3.jl/dev/)
[![Build Status](https://github.com//AWSCS3.jl/actions/workflows/Coverage.yml/badge.svg?branch=master)](https://github.com//AWSCS3.jl/actions/workflows/Coverage.yml?query=branch%3Amaster)
[![Coverage](https://codecov.io/gh//AWSCS3.jl/branch/master/graph/badge.svg)](https://codecov.io/gh//AWSCS3.jl)
[![Registry](https://img.shields.io/badge/registry-Green-green)](https://github.com/bhftbootcamp/Green)

A lightweight, high-performance Julia client for S3-compatible object storage (AWS S3, etc.). Built on the AWS C SDK for maximum throughput.

## Installation

To install AWSCS3, simply use the Julia package manager:

```julia
] add "AWSCS3"
```

## Usage

Let's look at some of the most used cases

```julia
using AWSCS3

client = s3_client(;
    host = "my_host",
    region = "us-east-1",
    access_key = ENV["S3_ACCESS_KEY"],
    secret_key = ENV["S3_SECRET_KEY"]
)

if !bucket_exists(client, "my-bucket")
    create_bucket(client, "my-bucket")
end

# Upload as text
put_object(client, "my-bucket", "demo/hello.txt", "Hello, World!")

# Upload as bytes
put_object(client, "my-bucket", "demo/data.bin", UInt8[0x01, 0x02, 0x03, 0x04])

# Download (bytes) + decode as text
body = get_object(client, "my-bucket", "demo/hello.txt") |> String

listing = list_objects(client, "my-bucket"; prefix="demo/")

for obj in listing
    println("Found $(obj.key) ($(obj.size) bytes)")
end

copy_res = copy_object(client, "my-bucket", "demo/hello.txt", "my-bucket", "demo/hello_copy.txt")

delete_object(client, "my-bucket", "demo/hello.txt")
delete_object(client, "my-bucket", "demo/hello_copy.txt")
delete_object(client, "my-bucket", "demo/data.bin")

close(client)
```

## Building from Source

To build the C shim library:

```bash
cd deps
./build_shim.sh
```

## Contributing

Contributions to AWSCS3.jl are welcome! If you encounter a bug, have a feature request, or would like to contribute code, please open an issue or a pull request on GitHub.
