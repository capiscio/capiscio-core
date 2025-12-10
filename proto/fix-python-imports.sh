#!/bin/bash
# Post-generate script to fix Python imports in generated protobuf files

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GEN_DIR="$SCRIPT_DIR/../../capiscio-sdk-python/capiscio_sdk/_rpc/gen/capiscio/v1"

echo "Fixing Python imports in $GEN_DIR..."

# Fix grpc files
for f in "$GEN_DIR"/*_grpc.py; do
  if [ -f "$f" ]; then
    echo "  Fixing $(basename $f)"
    sed -i '' 's/from capiscio\.v1/from capiscio_sdk._rpc.gen.capiscio.v1/g' "$f"
  fi
done

# Fix pb2 files (for any cross-imports)
for f in "$GEN_DIR"/*_pb2.py; do
  if [ -f "$f" ]; then
    # Check if file has wrong imports
    if grep -q "from capiscio\.v1" "$f" 2>/dev/null; then
      echo "  Fixing $(basename $f)"
      sed -i '' 's/from capiscio\.v1/from capiscio_sdk._rpc.gen.capiscio.v1/g' "$f"
    fi
  fi
done

echo "Done!"
