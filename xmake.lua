set_languages("cxx23")
set_version("0.1.0")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})

add_requires("xdl")

target("zygisk-fripack-loader")
    add_files("src/*.cc")
    set_kind("shared")
    add_packages("xdl")
