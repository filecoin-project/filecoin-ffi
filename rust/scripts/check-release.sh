#!/usr/bin/env bash

set -Exeuo pipefail

main() {
    if [[ -z "$1" ]]
    then
        (>&2 echo '[check-release/main] Error: script requires a release (gzipped) tarball path, e.g. "/tmp/filecoin-ffi-Darwin-standard.tar.tz"')
        exit 1
    fi

    # make sure we have a token set, api requests won't work otherwise
    if [ -z $GITHUB_TOKEN ]; then
        (>&2 echo "[check-release/main] \$GITHUB_TOKEN not set, check failed")
        exit 1
    fi

    # make sure we have a release url set
    if [ -z "$GITHUB_RELEASE_URL" ]; then
        (>&2 echo "[check-release/main] \$GITHUB_RELEASE_URL not set, check failed")
        exit 1
    fi

    local __release_file=$1
    local __release_url="${GITHUB_RELEASE_URL}"
    local __release_target="$(basename $__release_file)"

    # see if the release already exists by tag
    local __release_response=`
        curl \
            --header "Authorization: token $GITHUB_TOKEN" \
            "$__release_url"
    `

    local __release_id=`echo $__release_response | jq '.id'`

    if [ "$__release_id" = "null" ]; then
        (>&2 echo '[check-release/main] release does not exist')
        exit 1
    fi

    local __release_target_asset=`echo $__release_response | jq -r ".assets | .[] | select(.name == \"$__release_target\")"`

    if [ -n "$__release_target_asset" ]; then
        (>&2 echo '[check-release/main] release asset exists')
        echo "true"
    else
        (>&2 echo '[check-release/main] release asset does not exist')
        echo "false"
    fi
}

main "$@"; exit
