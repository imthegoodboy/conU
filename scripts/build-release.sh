#!/usr/bin/env sh
set -eu

TARGET="${TARGET:-}"
PROFILE="${PROFILE:-release}"
OUT_DIR="${OUT_DIR:-dist}"
PACKAGE_SUFFIX="${PACKAGE_SUFFIX:-}"
SIGNING_REQUIRED="${CONU_SIGNING_REQUIRED:-0}"
MACOS_CODESIGN_IDENTITY="${CONU_MACOS_CODESIGN_IDENTITY:-}"
MACOS_KEYCHAIN="${CONU_MACOS_KEYCHAIN:-}"
MACOS_NOTARY_KEYCHAIN_PROFILE="${CONU_MACOS_NOTARY_KEYCHAIN_PROFILE:-}"
RELEASE_ARCHIVE_FORMAT="${CONU_RELEASE_ARCHIVE_FORMAT:-}"

REPO="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OS_NAME="$(uname -s)"
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
cp docs/*.md "$DOC_DIR/"
cp -R packaging "$PACKAGE_ROOT/"

toml_bool() {
  if [ "$1" = "1" ]; then
    printf true
  else
    printf false
  fi
}

codesign_binary() {
  binary_path="$1"
  if [ -n "$MACOS_KEYCHAIN" ]; then
    codesign --force --options runtime --timestamp --sign "$MACOS_CODESIGN_IDENTITY" --keychain "$MACOS_KEYCHAIN" "$binary_path"
  else
    codesign --force --options runtime --timestamp --sign "$MACOS_CODESIGN_IDENTITY" "$binary_path"
  fi
  codesign --verify --strict --verbose=2 "$binary_path"
}

notarize_archive() {
  archive_path="$1"
  if [ -n "$MACOS_KEYCHAIN" ]; then
    xcrun notarytool submit "$archive_path" --keychain "$MACOS_KEYCHAIN" --keychain-profile "$MACOS_NOTARY_KEYCHAIN_PROFILE" --wait
  else
    xcrun notarytool submit "$archive_path" --keychain-profile "$MACOS_NOTARY_KEYCHAIN_PROFILE" --wait
  fi
}

MACOS_CODESIGNED=0
MACOS_NOTARIZED=0
if [ "$OS_NAME" = "Darwin" ]; then
  if [ -n "$MACOS_CODESIGN_IDENTITY" ]; then
    for binary in conu conud conu-relay conu-mcp; do
      codesign_binary "$BIN_DIR/$binary"
    done
    MACOS_CODESIGNED=1
  elif [ "$SIGNING_REQUIRED" = "1" ]; then
    echo "CONU_SIGNING_REQUIRED=1 but CONU_MACOS_CODESIGN_IDENTITY is not configured" >&2
    exit 1
  fi
fi

if [ -z "$RELEASE_ARCHIVE_FORMAT" ]; then
  if [ "$OS_NAME" = "Darwin" ]; then
    RELEASE_ARCHIVE_FORMAT="zip"
  else
    RELEASE_ARCHIVE_FORMAT="tar.gz"
  fi
fi

if [ "$OS_NAME" = "Darwin" ] && [ -n "$MACOS_NOTARY_KEYCHAIN_PROFILE" ] && [ "$MACOS_CODESIGNED" != "1" ]; then
  echo "CONU_MACOS_NOTARY_KEYCHAIN_PROFILE requires CONU_MACOS_CODESIGN_IDENTITY" >&2
  exit 1
fi
if [ "$OS_NAME" = "Darwin" ] && [ -n "$MACOS_NOTARY_KEYCHAIN_PROFILE" ]; then
  MACOS_NOTARIZED=1
elif [ "$OS_NAME" = "Darwin" ] && [ "$SIGNING_REQUIRED" = "1" ]; then
  echo "CONU_SIGNING_REQUIRED=1 but CONU_MACOS_NOTARY_KEYCHAIN_PROFILE is not configured" >&2
  exit 1
fi

cat > "$PACKAGE_ROOT/manifest.toml" <<EOF
name = "conU"
version = "$VERSION"
target = "$TARGET_SUFFIX"
profile = "$PROFILE"
payload_contents_included = false
windows_authenticode_signed = false
macos_codesigned = $(toml_bool "$MACOS_CODESIGNED")
macos_notarized = $(toml_bool "$MACOS_NOTARIZED")
linux_signature_policy = "sha256-checksum-and-github-artifact-attestation"
EOF

if [ "$RELEASE_ARCHIVE_FORMAT" = "zip" ]; then
  ARCHIVE="$PACKAGE_ROOT.zip"
  rm -f "$ARCHIVE"
  if command -v ditto >/dev/null 2>&1; then
    ditto -c -k --keepParent "$PACKAGE_ROOT" "$ARCHIVE"
  elif command -v zip >/dev/null 2>&1; then
    (cd "$REPO/$OUT_DIR" && zip -qr "$(basename "$ARCHIVE")" "$(basename "$PACKAGE_ROOT")")
  else
    echo "zip archive requested but neither ditto nor zip is available" >&2
    exit 1
  fi
  if [ "$OS_NAME" = "Darwin" ] && [ "$MACOS_NOTARIZED" = "1" ]; then
    notarize_archive "$ARCHIVE"
  fi
  if command -v shasum >/dev/null 2>&1; then
    HASH="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
  else
    HASH="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$HASH" "$(basename "$ARCHIVE")" > "$ARCHIVE.sha256"
  echo "created $ARCHIVE"
  echo "created $ARCHIVE.sha256"
elif [ "$RELEASE_ARCHIVE_FORMAT" = "tar.gz" ] && command -v tar >/dev/null 2>&1; then
  ARCHIVE="$PACKAGE_ROOT.tar.gz"
  rm -f "$ARCHIVE"
  tar -C "$REPO/$OUT_DIR" -czf "$ARCHIVE" "$(basename "$PACKAGE_ROOT")"
  if command -v sha256sum >/dev/null 2>&1; then
    HASH="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
  else
    HASH="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$HASH" "$(basename "$ARCHIVE")" > "$ARCHIVE.sha256"
  echo "created $ARCHIVE"
  echo "created $ARCHIVE.sha256"
elif [ "$RELEASE_ARCHIVE_FORMAT" = "tar.gz" ]; then
  echo "created $PACKAGE_ROOT"
else
  echo "unsupported release archive format: $RELEASE_ARCHIVE_FORMAT" >&2
  exit 1
fi
