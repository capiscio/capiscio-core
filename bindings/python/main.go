package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"encoding/json"
	"unsafe"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/capiscio/capiscio-core/pkg/report"
	"github.com/capiscio/capiscio-core/pkg/scoring"
)

// ValidateAgentCard validates an Agent Card JSON string.
// checkLive: 0 for false, 1 for true.
// Returns a JSON string containing the ValidationResult.
// The returned string must be freed using FreeString.
//
//export ValidateAgentCard
func ValidateAgentCard(jsonStr *C.char, checkLive int) *C.char {
	goStr := C.GoString(jsonStr)

	var card agentcard.AgentCard
	if err := json.Unmarshal([]byte(goStr), &card); err != nil {
		return C.CString(fmtError("JSON_PARSE_ERROR", err.Error()))
	}

	// Use default configuration for now
	engine := scoring.NewEngine(nil)
	ctx := context.Background()

	// checkLive: 0 = false, 1 = true
	doLive := checkLive != 0

	result, err := engine.Validate(ctx, &card, doLive)
	if err != nil {
		return C.CString(fmtError("ENGINE_ERROR", err.Error()))
	}

	resBytes, err := json.Marshal(result)
	if err != nil {
		return C.CString(fmtError("JSON_MARSHAL_ERROR", err.Error()))
	}

	return C.CString(string(resBytes))
}

// FreeString frees the memory allocated for a C string by Go.
//
//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func fmtError(code, msg string) string {
	res := report.ValidationResult{
		Success: false,
		Issues: []report.ValidationIssue{
			{
				Code:     code,
				Message:  msg,
				Severity: "error",
			},
		},
	}
	bytes, _ := json.Marshal(res)
	return string(bytes)
}

func main() {}
