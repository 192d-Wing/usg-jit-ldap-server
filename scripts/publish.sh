#!/bin/bash

echo "Enter Version to be published (X.X.X):"
read -r version

sed -i '' -E "s/^version = \"[0-9]+\.[0-9]+\.[0-9]+\"/version = \"$version\"/" Cargo.toml

git add Cargo.toml
git commit -m "release: Bump version to $version"
git tag v$version
git push origin v$version
git push origin