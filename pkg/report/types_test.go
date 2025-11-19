package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationResult_AddError(t *testing.T) {
	res := &ValidationResult{Success: true}
	res.AddError("ERR001", "Something went wrong", "field1")

	assert.False(t, res.Success)
	assert.Len(t, res.Issues, 1)
	assert.Equal(t, "ERR001", res.Issues[0].Code)
	assert.Equal(t, "error", res.Issues[0].Severity)
	assert.Equal(t, "field1", res.Issues[0].Field)
}

func TestValidationResult_AddWarning(t *testing.T) {
	res := &ValidationResult{Success: true}
	res.AddWarning("WARN001", "Be careful", "field2")

	assert.True(t, res.Success) // Warning should not set Success to false
	assert.Len(t, res.Issues, 1)
	assert.Equal(t, "WARN001", res.Issues[0].Code)
	assert.Equal(t, "warning", res.Issues[0].Severity)
	assert.Equal(t, "field2", res.Issues[0].Field)
}

func TestValidationResult_MixedIssues(t *testing.T) {
	res := &ValidationResult{Success: true}
	res.AddWarning("W1", "Warn", "f1")
	res.AddError("E1", "Err", "f2")

	assert.False(t, res.Success)
	assert.Len(t, res.Issues, 2)
	assert.Equal(t, "warning", res.Issues[0].Severity)
	assert.Equal(t, "error", res.Issues[1].Severity)
}
