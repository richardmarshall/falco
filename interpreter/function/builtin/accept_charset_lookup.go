// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Accept_charset_lookup_Name = "accept.charset_lookup"

var Accept_charset_lookup_ArgumentTypes = []value.Type{value.StringType, value.StringType, value.StringType}

func Accept_charset_lookup_Validate(args []value.Value) error {
	if len(args) != 3 {
		return errors.ArgumentNotEnough(Accept_charset_lookup_Name, 3, args)
	}
	args = shared.CoerceArguments(args, Accept_charset_lookup_ArgumentTypes)
	for i := range args {
		if args[i].Type() != Accept_charset_lookup_ArgumentTypes[i] {
			return errors.TypeMismatch(Accept_charset_lookup_Name, i+1, Accept_charset_lookup_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of accept.charset_lookup
// Arguments may be:
// - STRING, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/content-negotiation/accept-charset-lookup/
func Accept_charset_lookup(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Accept_charset_lookup_Validate(args); err != nil {
		return value.Null, err
	}

	lookup := value.Unwrap[*value.String](args[0])
	defaultValue := value.Unwrap[*value.String](args[1])
	accept := value.Unwrap[*value.String](args[2])

	var charsets []string
	for _, v := range strings.Split(lookup.Value, ":") {
		charsets = append(charsets, v)
	}

	index := len(charsets)
	for _, v := range strings.Split(accept.Value, ",") {
		v = strings.TrimSpace(v)
		if idx := strings.Index(v, ";"); idx != -1 {
			v = v[0:idx]
		}
		for i := range charsets {
			if charsets[i] == v {
				if i < index {
					index = i
				}
			}
		}
	}

	if index < len(charsets) {
		return &value.String{Value: charsets[index]}, nil
	}
	return defaultValue, nil
}
