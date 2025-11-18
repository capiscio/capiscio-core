import ctypes
import json
import os
import sys

# Load the shared library
lib_path = os.path.join(os.path.dirname(__file__), "libcapiscio.so")
if not os.path.exists(lib_path):
    print(f"Error: {lib_path} not found. Run 'make build-python' first.")
    sys.exit(1)

lib = ctypes.CDLL(lib_path)

# Define argument and return types
lib.ValidateAgentCard.argtypes = [ctypes.c_char_p, ctypes.c_int]
lib.ValidateAgentCard.restype = ctypes.c_void_p

lib.FreeString.argtypes = [ctypes.c_void_p]
lib.FreeString.restype = None

def validate_card(card_json: dict, check_live: bool = False) -> dict:
    json_str = json.dumps(card_json).encode('utf-8')
    live_int = 1 if check_live else 0
    
    # Call Go function
    result_ptr = lib.ValidateAgentCard(json_str, live_int)
    
    # Read string from pointer
    result_str = ctypes.cast(result_ptr, ctypes.c_char_p).value.decode('utf-8')
    
    # Free the memory allocated by Go
    lib.FreeString(result_ptr)
    
    return json.loads(result_str)

# Test Data
sample_card = {
    "protocolVersion": "0.3.0",
    "name": "Test Agent",
    "version": "1.0.0",
    "url": "https://example.com/agent",
    "skills": [
        {
            "id": "skill-1", 
            "name": "Test Skill", 
            "description": "A test skill", 
            "tags": ["test"]
        }
    ]
}

print("Validating sample card...")
result = validate_card(sample_card)
print(json.dumps(result, indent=2))

if result['success']:
    print("\n✅ Validation Successful!")
else:
    print("\n❌ Validation Failed!")
