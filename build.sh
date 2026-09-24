#!/usr/bin/env bash
set -euo pipefail

rm -rf dist/
uv build
# Publish (requires UV_PUBLISH_TOKEN or interactive credentials):
# uv publish
