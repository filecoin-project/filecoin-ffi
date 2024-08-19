# Release Process

This document describes the process for releasing a new version of the `filecoin-ffi` project.

## Current State

1. Create a pull request which updates the `version` in the [top-level `version.json` file](https://github.com/filecoin-project/filecoin-ffi/blob/master/version.json).
   - Title the PR `chore: X.Y.Z release`
2. On pull request creation, a [Release Checker](.github/workflows/release-check.yml) workflow will run. It will perform the following actions:
    1. Extract the version from the top-level `version.json` file.
    2. Check if a git tag for the version already exists. Continue only if it does not.
    3. Create a draft GitHub release with the version as the tag.  (A git tag with this version string will be created when the release is published.)
    4. Comment on the pull request with a link to the draft release.
    5. Build the project for Linux (X64), Linux (ARM64), and MacOS.
    7. Upload the built assets to the draft release (replace any existing assets with the same name).
3. On pull request merge, a [Releaser](.github/workflows/release.yml) workflow will run. It will perform the following actions:
    1. Extract the version from the top-level `version.json` file.
    2. Check if a git tag for the version already exists. Continue only if it does not.
    3. Check if a draft GitHub release with the version as the tag exists.
    4. If the draft release exists, publish it. Otherwise, create and publish a new release with the version as the git tag.  Publishing the release creates the git tag.

## Known Limitations

1. If one pushes an update to the `version` in the top-level `version.json` file without creating a pull request, the Release Checker workflow will not run. Hence, the release assets will not be automatically built and uploaded.

## Possible Improvements

1. Add a check to the [Releaser](.github/workflows/release.yml) workflow to ensure that the created/published release contains the expected assets. If it does not, create them and run the [publish-release.sh](rust/scripts/publish-release.sh) script to upload the missing assets.
