// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of utf8.is_valid
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/utf8-is-valid/
func Test_Utf8_is_valid(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{
			input:  `abc123`,
			expect: true,
		},
		{
			input:  "/foo/bar",
			expect: true,
		},
		{
			input:  "?p=q&x=y",
			expect: true,
		},
		{
			input:  `"`,
			expect: true,
		},
		{
			input:  "\n",
			expect: true,
		},
		{
			input:  "	",
			expect: true,
		},
		{
			input:  "αβγ",
			expect: true,
		},
		{
			input:  string([]byte{0xFF}),
			expect: false,
		},
		{
			input:  string([]byte{0x61, 0x20, 0x2B, 0x20, 0xCC}),
			expect: false,
		},
		{
			input:  "😁",
			expect: true,
		},
	}

	for _, tt := range tests {
		ret, err := Utf8_is_valid(&context.Context{}, &value.String{Value: tt.input})
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}
		if ret.Type() != value.BooleanType {
			t.Errorf("Unexpected return type, expect=BOOL, got=%s", ret.Type())
		}
		v := value.Unwrap[*value.Boolean](ret)
		if v.Value != tt.expect {
			t.Errorf("Return value unmatch, expect=%t, got=%t", tt.expect, v.Value)
		}
	}
}
