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
       - If for some reason asset uploading fails, the [Upload Release Assets](.github/workflows/upload-release-assets.yml) workflow can be manually run.
3. On pull request merge, a [Releaser](.github/workflows/releaser.yml) workflow will run. It will perform the following actions:
    1. Extract the version from the top-level `version.json` file.
    2. Check if a git tag for the version already exists. Continue only if it does not.
    3. Check if a draft GitHub release with the version as the tag exists.
    4. If the draft release exists, publish it. Otherwise, create and publish a new release with the version as the git tag.  Publishing the release creates the git tag.
    5. Check if the release contains Linux (X64), Linux (ARM64), and MacOS assets. If not:
        1. Build the missing assets.
        2. Upload the built assets to the release.
           - If for some reason asset uploading fails, the [Upload Release Assets](.github/workflows/upload-release-assets.yml) workflow can be manually run.


## Known Limitations

1. If one pushes an update to the `version` in the top-level `version.json` file without creating a pull request, the Release Checker workflow will not run. Hence, the release assets will not be automatically built and uploaded.
