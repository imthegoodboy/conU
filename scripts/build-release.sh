#!/usr/bin/env sh
set -eu

TARGET="${TARGET:-}"
PROFILE="${PROFILE:-release}"
OUT_DIR="${OUT_DIR:-dist}"
PACKAGE_SUFFIX="${PACKAGE_SUFFIX:-}"

REPO="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PYTHON_BIN="python"
fi
VERSION="$(cd "$REPO" && cargo metadata --format-version 1 --no-deps | "$PYTHON_BIN" -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"]=="conu-cli"))')"

TARGET_ARGS=""
TARGET_SUFFIX="host"
if [ -n "$TARGET" ]; then
  TARGET_ARGS="--target $TARGET"
  TARGET_SUFFIX="$TARGET"
fi
if [ -n "$PACKAGE_SUFFIX" ]; then
  TARGET_SUFFIX="$PACKAGE_SUFFIX"
fi

PROFILE_ARGS=""
if [ "$PROFILE" = "release" ]; then
  PROFILE_ARGS="--release"
fi

cd "$REPO"
cargo build --workspace $PROFILE_ARGS $TARGET_ARGS

if [ -n "$TARGET" ]; then
  BUILD_DIR="$REPO/target/$TARGET/$PROFILE"
else
  BUILD_DIR="$REPO/target/$PROFILE"
fi

PACKAGE_ROOT="$REPO/$OUT_DIR/conu-$VERSION-$TARGET_SUFFIX"
BIN_DIR="$PACKAGE_ROOT/bin"
DOC_DIR="$PACKAGE_ROOT/docs"
rm -rf "$PACKAGE_ROOT"
mkdir -p "$BIN_DIR" "$DOC_DIR"

for binary in conu conud conu-relay conu-mcp; do
  if [ ! -f "$BUILD_DIR/$binary" ]; then
    echo "missing built binary $BUILD_DIR/$binary" >&2
    exit 1
  fi
  cp "$BUILD_DIR/$binary" "$BIN_DIR/"
done

cp README.md "$PACKAGE_ROOT/"
cp docs/user-install-and-agent-guide.md "$DOC_DIR/"
cp docs/production-readiness.md "$DOC_DIR/"
cp docs/release-checklist.md "$DOC_DIR/"
cp docs/observability.md "$DOC_DIR/"
cp docs/distribution-and-hosting.md "$DOC_DIR/"
cp -R packaging "$PACKAGE_ROOT/"

cat > "$PACKAGE_ROOT/manifest.toml" <<EOF
name = "conU"
version = "$VERSION"
target = "$TARGET_SUFFIX"
profile = "$PROFILE"
payload_contents_included = false
EOF

if command -v tar >/dev/null 2>&1; then
  ARCHIVE="$PACKAGE_ROOT.tar.gz"
  tar -C "$REPO/$OUT_DIR" -czf "$ARCHIVE" "$(basename "$PACKAGE_ROOT")"
  if command -v sha256sum >/dev/null 2>&1; then
    HASH="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
  else
    HASH="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$HASH" "$(basename "$ARCHIVE")" > "$ARCHIVE.sha256"
  echo "created $ARCHIVE"
  echo "created $ARCHIVE.sha256"
else
  echo "created $PACKAGE_ROOT"
fi
