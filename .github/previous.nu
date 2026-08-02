const API_VERSION = "2022-11-28"

const DEFAULT_WORKFLOW_FILE = "build.yml"
const DEFAULT_ARTIFACT_NAME = "build"
const DEFAULT_BUILD_DIR = "build"
const DEFAULT_ZIP_PATH = "/tmp/previous.zip"
const DEFAULT_PUBLISHED_BRANCH = "Sukka"
const DEFAULT_REQUIRED_SEED_PATHS = [
    "404.html"
    "Clash"
    "Internal"
    "LegacyClashPremium"
    "List"
    "Mock"
    "Modules"
    "README.md"
    "Surfboard"
    "_headers"
    "index.html"
]
const DEFAULT_EXTERNAL_FALLBACK_SOURCE = {
    owner: "SukkaLab"
    repo: "ruleset.skk.moe"
    ref: "master"
    seed_paths: []
}

def github_headers [] {
    {
        Authorization: $"Bearer ($env.GITHUB_TOKEN?)"
        Accept: "application/vnd.github+json"
        "X-GitHub-Api-Version": $API_VERSION
    }
}

def github_api [] {
    $"https://api.github.com/repos/($env.GITHUB_REPOSITORY?)"
}

def github_get [path: string] {
    http get --headers (github_headers) (github_api | path join $path)
}

def github_get_raw [url: string] {
    http get --headers (github_headers) --raw $url
}

def list_field [value: any field: string] {
    try {
        $value | get $field
    } catch {
        []
    }
}

def first-non-empty [] {
    $in
        | where {|value| $value != null and $value != "" }
        | first
}

def artifact-url [artifact: any] {
    $artifact
        | default {}
        | get archive_download_url?
        | default ""
}

def active-artifacts-at [path: string] {
    list_field (github_get $path) artifacts
        | where {|artifact| ($artifact | get expired? | default false) == false }
}

def workflow-runs [workflow_file: string] {
    list_field (
        github_get $"actions/workflows/($workflow_file)/runs?branch=($env.GITHUB_REF_NAME?)&status=success&per_page=10"
    ) workflow_runs
}

def artifact-in-runs [workflow_file: string artifact_name: string] {
    workflow-runs $workflow_file
        | each {|run|
            let artifact = (
                active-artifacts-at $"actions/runs/($run.id)/artifacts?per_page=100"
                    | where name == $artifact_name
                    | first
            )
            artifact-url $artifact
        }
        | first-non-empty
}

def artifact-in-repository [artifact_name: string] {
    let artifact = (active-artifacts-at $"actions/artifacts?name=($artifact_name)&per_page=100" | first)
    artifact-url $artifact
}

def resolve-artifact-url [workflow_file: string artifact_name: string] {
    [
        (artifact-in-runs $workflow_file $artifact_name)
        (artifact-in-repository $artifact_name)
    ]
        | first-non-empty
        | default ""
}

def ensure-dir [path: string] {
    if not ($path | path exists) {
        mkdir $path
    }
}

def save-url [url: string path: string] {
    github_get_raw $url
        | save --raw -f $path
}

def unzip-into [zip_path: string build_dir: string] {
    ensure-dir $build_dir
    ^unzip -q $zip_path -d $build_dir
}

def restore-artifact [url: string zip_path: string build_dir: string] {
    try {
        save-url $url $zip_path
        unzip-into $zip_path $build_dir
    } catch {}
}

def repo-parts [repo_slug: string] {
    let parts = ($repo_slug | split row "/")

    if ($parts | length) == 2 {
        { owner: ($parts | get 0) repo: ($parts | get 1) }
    } else {
        null
    }
}

def fallback-sources [fallback_owner: string fallback_repo: string fallback_ref: string] {
    let current_repo = ($env.GITHUB_REPOSITORY? | default "")
    let current_source = (
        repo-parts $current_repo
            | default {}
            | merge { ref: $DEFAULT_PUBLISHED_BRANCH seed_paths: [] }
    )

    [
        (if $current_repo == "" { null } else { $current_source })
        ($DEFAULT_EXTERNAL_FALLBACK_SOURCE | merge {
            owner: $fallback_owner
            repo: $fallback_repo
            ref: $fallback_ref
        })
    ]
        | where {|source| $source != null }
}

def github-archive-url [source: record] {
    $"https://github.com/($source.owner)/($source.repo)/archive/refs/heads/($source.ref).tar.gz"
}

def github-archive-prefix [source: record] {
    $"($source.repo)-($source.ref)"
}

def missing-seed-paths [build_dir: string required_paths: list<string>] {
    $required_paths
        | where {|relative_path| not (($build_dir | path join $relative_path) | path exists) }
}

def root-seed-mappings [source_root: string] {
    ls $source_root
        | each {|entry|
            {
                source: ($entry.name | path basename)
                destination_dir: ""
            }
        }
}

def effective-seed-mappings [source_root: string source: record] {
    let configured_paths = ($source | get seed_paths? | default [])

    if ($configured_paths | is-empty) {
        root-seed-mappings $source_root
    } else {
        $configured_paths
    }
}

def destination-root [build_dir: string mapping: record] {
    if $mapping.destination_dir == "" {
        $build_dir
    } else {
        $build_dir | path join $mapping.destination_dir
    }
}

def copy-seed-path [source_root: string build_dir: string mapping: record] {
    let source_path = ($source_root | path join $mapping.source)
    let target_root = (destination-root $build_dir $mapping)

    ensure-dir $target_root
    if ($source_path | path type) == "dir" {
        cp -r $source_path $target_root
    } else {
        cp $source_path $target_root
    }
}

def seed-from-source [build_dir: string source: record] {
    let workdir = (^mktemp -d | str trim)
    let archive_path = ($workdir | path join "seed.tar.gz")
    let extract_dir = ($workdir | path join "extract")

    try {
        save-url (github-archive-url $source) $archive_path

        ensure-dir $extract_dir
        ^tar -xzf $archive_path -C $extract_dir

        let source_root = ($extract_dir | path join (github-archive-prefix $source))
        effective-seed-mappings $source_root $source
            | each {|mapping| copy-seed-path $source_root $build_dir $mapping }
    } catch {}

    rm -rf $workdir
}

def seed-build-dir [
    build_dir: string
    fallback_sources: list<record>
    required_paths: list<string> = $DEFAULT_REQUIRED_SEED_PATHS
] {
    for source in $fallback_sources {
        if (missing-seed-paths $build_dir $required_paths | is-empty) {
            return
        }

        seed-from-source $build_dir $source
    }
}

export def main [
    --workflow-file: string = $DEFAULT_WORKFLOW_FILE
    --artifact-name: string = $DEFAULT_ARTIFACT_NAME
    --build-dir: string = $DEFAULT_BUILD_DIR
    --zip-path: string = $DEFAULT_ZIP_PATH
    --fallback-owner: string = $DEFAULT_EXTERNAL_FALLBACK_SOURCE.owner
    --fallback-repo: string = $DEFAULT_EXTERNAL_FALLBACK_SOURCE.repo
    --fallback-ref: string = $DEFAULT_EXTERNAL_FALLBACK_SOURCE.ref
] {
    let fallback_sources = (fallback-sources $fallback_owner $fallback_repo $fallback_ref)

    let artifact_url = (resolve-artifact-url $workflow_file $artifact_name)
    if $artifact_url != "" {
        restore-artifact $artifact_url $zip_path $build_dir
    }

    seed-build-dir $build_dir $fallback_sources
}

main
