#!/usr/bin/env bash

set -Exeuo pipefail

main() {
    if [[ -z "$1" ]]
    then
        (>&2 echo '[publish-release/main] Error: script requires a release (gzipped) tarball path, e.g. "/tmp/filecoin-ffi-Darwin-standard.tar.tz"')
        exit 1
    fi

    if [[ -z "$2" ]]
    then
        (>&2 echo '[publish-release/main] Error: script requires a release name, e.g. "filecoin-ffi-Darwin-standard" or "filecoin-ffi-Linux-standard"')
        exit 1
    fi

    local __release_file=$1
    local __release_url="${GITHUB_RELEASE_URL}"
    local __release_target="$(basename $__release_file)"

    # make sure we have a token set, api requests won't work otherwise
    if [ -z $GITHUB_TOKEN ]; then
        (>&2 echo "[publish-release/main] \$GITHUB_TOKEN not set, publish failed")
        exit 1
    fi

    # make sure we have a release url set
    if [ -z "$GITHUB_RELEASE_URL" ]; then
        (>&2 echo "[publish-release/main] \$GITHUB_RELEASE_URL not set, publish failed")
        exit 1
    fi

    # see if the release already exists by tag
    local __release_response=`
        curl \
            --header "Authorization: token $GITHUB_TOKEN" \
            "$__release_url"
    `

    local __release_id=`echo $__release_response | jq '.id'`

    if [ "$__release_id" = "null" ]; then
        (>&2 echo '[publish-release/main] release does not exist')
        exit 1
    fi

    __release_target_asset=`echo $__release_response | jq -r ".assets | .[] | select(.name == \"$release_target\")"`

    if [ -n "$__release_target_asset" ]; then
        (>&2 echo "[publish-release/main] $__release_target_asset already exists, deleting")

        __release_target_asset_url=`echo $__release_target_asset | jq -r '.url'`

        curl \
        --request DELETE \
        --header "Authorization: token $GITHUB_TOKEN" \
        "$__release_target_asset_url"
    fi

    __release_upload_url=`echo $__release_response | jq -r '.upload_url' | cut -d'{' -f1`

    curl \
        --request POST \
        --header "Authorization: token $GITHUB_TOKEN" \
        --header "Content-Type: application/octet-stream" \
        --data-binary "@$__release_file" \
        "$__release_upload_url?name=$__release_target"

    (>&2 echo '[publish-release/main] release file uploaded')
}

main "$@"; exit
