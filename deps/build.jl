#!/usr/bin/env julia

const SHIM_SCRIPT = joinpath(@__DIR__, "build_shim.sh")
const PROJECT_DIR = dirname(@__DIR__)
const LOAD_PATH = join(["@", "@v#.#", "@stdlib"], Sys.iswindows() ? ";" : ":")

bash = get(ENV, "BASH", Sys.which("bash"))

cd(@__DIR__) do
    env_overrides = ("JULIA_PROJECT" => PROJECT_DIR, "JULIA_LOAD_PATH" => LOAD_PATH)
    withenv(env_overrides...) do
        run(`$bash $SHIM_SCRIPT`)
    end
end
