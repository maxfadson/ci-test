using AWSCS3
using Documenter

DocMeta.setdocmeta!(AWSCS3, :DocTestSetup, :(using AWSCS3); recursive = true)

makedocs(;
    modules = [AWSCS3],
    sitename = "AWSCS3.jl",
    format = Documenter.HTML(;
        repolink = "https://github.com//AWSCS3.jl",
        canonical = "https://.github.io/AWSCS3.jl",
        edit_link = "master",
        assets = ["assets/favicon.ico"],
        sidebar_sitename = true,  # Set to 'false' if the package logo already contain its name
    ),
    pages = [
        "Home"    => "index.md",
        "Content" => "pages/content.md",
        # Add your pages here ...
    ],
    warnonly = [:doctest, :missing_docs],
)

deploydocs(;
    repo = "github.com//AWSCS3.jl",
    devbranch = "master",
    push_preview = true,
)
