function capture_xml_element(pattern::Regex, text::AbstractString)::Union{Nothing,String}
    m = match(pattern, text)
    return m === nothing ? nothing : m.captures[1]
end

function parse_bucket_names(body::Vector{UInt8})::Vector{String}
    text = String(copy(body))
    names = String[]
    for m in eachmatch(r"<Name>([^<]+)</Name>", text)
        push!(names, m.captures[1])
    end
    return names
end

function parse_list_objects_text(text::AbstractString)::Vector{S3Object}
    objects = S3Object[]

    for m in eachmatch(r"<Contents>(.*?)</Contents>"s, text)
        content = m.captures[1]
        key = capture_xml_element(r"<Key>([^<]+)</Key>", content)
        size_str = capture_xml_element(r"<Size>([^<]+)</Size>", content)
        last_modified = capture_xml_element(r"<LastModified>([^<]+)</LastModified>", content)
        etag = capture_xml_element(r"<ETag>([^<]+)</ETag>", content)

        if key !== nothing
            push!(objects, S3Object(
                key,
                size_str !== nothing ? parse(Int, size_str) : 0,
                something(last_modified, ""),
                etag !== nothing ? replace(etag, "\"" => "") : ""
            ))
        end
    end

    return objects
end

function parse_list_objects(body::Vector{UInt8})::Vector{S3Object}
    text = String(copy(body))
    return parse_list_objects_text(text)
end

function parse_list_objects_detailed(body::Vector{UInt8})::S3ListResult
    text = String(copy(body))
    objects = parse_list_objects_text(text)

    common_prefixes = String[]
    for m in eachmatch(r"<CommonPrefixes>.*?<Prefix>([^<]+)</Prefix>.*?</CommonPrefixes>"s, text)
        push!(common_prefixes, m.captures[1])
    end

    is_truncated = occursin(r"<IsTruncated>true</IsTruncated>"i, text)
    next_token = capture_xml_element(r"<NextContinuationToken>([^<]+)</NextContinuationToken>", text)

    return S3ListResult(objects, common_prefixes, is_truncated, next_token)
end

function parse_copy_result(body::Vector{UInt8})::S3CopyResult
    text = String(copy(body))
    etag = capture_xml_element(r"<ETag>([^<]+)</ETag>", text)
    last_modified = capture_xml_element(r"<LastModified>([^<]+)</LastModified>", text)
    return S3CopyResult(
        etag !== nothing ? replace(etag, "\"" => "") : "",
        something(last_modified, "")
    )
end
