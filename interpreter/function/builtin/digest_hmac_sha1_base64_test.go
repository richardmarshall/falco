// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of digest.hmac_sha1_base64
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-hmac-sha1-base64/
func Test_Digest_hmac_sha1_base64(t *testing.T) {
	ret, err := Digest_hmac_sha1_base64(
		&context.Context{},
		&value.String{Value: "key"},
		&value.String{Value: "input"},
	)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if ret.Type() != value.StringType {
		t.Errorf("Unexpected return type, expect=STRING, got=%s", ret.Type())
	}
	v := value.Unwrap[*value.String](ret)
	expect := "hRO7NVB2zOKuXrnzmatcr9unyKI="
	if v.Value != expect {
		t.Errorf("return value unmach, expect=%s, got=%s", expect, v.Value)
	}
}
