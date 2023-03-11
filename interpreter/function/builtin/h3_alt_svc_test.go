// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
)

// Fastly built-in function testing implementation of h3.alt_svc
// Arguments may be:
// Reference: https://developer.fastly.com/reference/vcl/functions/tls-and-http/h3-alt-svc/
func Test_H3_alt_svc(t *testing.T) {
	ctx := &context.Context{}
	ret, err := H3_alt_svc(
		ctx,
	)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if ret != nil {
		t.Errorf("Return type must be nil")
	}

	// compare stacked result
	if ctx.H3AltSvc != true {
		t.Errorf("AltSvc should be true, got=%t", ctx.H3AltSvc)
	}
}
