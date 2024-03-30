// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of regsub
// Arguments may be:
// - STRING, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/regsub/
func Test_Regsub(t *testing.T) {
	tests := []struct {
		input       string
		pattern     string
		replacement string
		expect      string
		isError     bool
	}{
		{input: "www.example.com", pattern: "www\\.", replacement: "", expect: "example.com"},
		{input: "/foo/bar/", pattern: "/$", replacement: "", expect: "/foo/bar"},
		{input: "aaaa", pattern: "a", replacement: "aa", expect: "aaaaa"},
		{input: "foo;bar;baz", pattern: "([^;]*)(;.*)?$", replacement: "\\1bar", expect: "foobar"},
	}

	for i, tt := range tests {
		ret, err := Regsub(
			&context.Context{},
			&value.String{Value: tt.input},
			&value.String{Value: tt.pattern},
			&value.String{Value: tt.replacement},
		)
		if err != nil {
			t.Errorf("[%d] Unexpected error: %s", i, err)
		}
		if ret.Type() != value.StringType {
			t.Errorf("[%d] Unexpected return type, expect=STRING, got=%s", i, ret.Type())
		}
		v := value.Unwrap[*value.String](ret)
		if v.Value != tt.expect {
			t.Errorf("[%d] Return value unmatch, expect=%s, got=%s", i, tt.expect, v.Value)
		}
	}
}
