#!/bin/sh
# Builds ask-pass-touchid into build/Build/Products/Release/.
#
# By default the binary is signed to run locally (ad-hoc), which needs no Apple
# developer account. To sign with your own team instead, run:
#   DEVELOPMENT_TEAM=<your team id> ./build.sh
# A stable signature means macOS won't ask again for keychain access after each rebuild.
set -e
cd "$(dirname "$0")"

if [ -n "$DEVELOPMENT_TEAM" ]; then
    set -- DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM" CODE_SIGN_IDENTITY="Apple Development"
fi

xcodebuild -project ask-pass-touchid.xcodeproj -scheme ask-pass-touchid \
    -configuration Release -destination "generic/platform=macOS" \
    -derivedDataPath build -quiet build "$@"

echo "Built build/Build/Products/Release/ask-pass-touchid"
