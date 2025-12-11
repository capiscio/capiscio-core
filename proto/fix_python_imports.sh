#!/bin/bash
# Fix Python protobuf imports after buf generate
# The generated files use "from capiscio.v1 import" but we need 
# "from capiscio_sdk._rpc.gen.capiscio.v1 import"

SDK_GEN_DIR="../../capiscio-sdk-python/capiscio_sdk/_rpc/gen/capiscio/v1"

if [ -d "$SDK_GEN_DIR" ]; then
    echo "Fixing Python protobuf imports..."
    sed -i '' 's/from capiscio\.v1 import/from capiscio_sdk._rpc.gen.capiscio.v1 import/g' "$SDK_GEN_DIR"/*.py
    echo "Done."
else
    echo "Warning: SDK gen directory not found: $SDK_GEN_DIR"
fi
