// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Accept_encoding_lookup_Name = "accept.encoding_lookup"

var Accept_encoding_lookup_ArgumentTypes = []value.Type{value.StringType, value.StringType, value.StringType}

func Accept_encoding_lookup_Validate(args []value.Value) error {
	if len(args) != 3 {
		return errors.ArgumentNotEnough(Accept_encoding_lookup_Name, 3, args)
	}
	args = shared.CoerceArguments(args, Accept_encoding_lookup_ArgumentTypes)
	for i := range args {
		if args[i].Type() != Accept_encoding_lookup_ArgumentTypes[i] {
			return errors.TypeMismatch(Accept_encoding_lookup_Name, i+1, Accept_encoding_lookup_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of accept.encoding_lookup
// Arguments may be:
// - STRING, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/content-negotiation/accept-encoding-lookup/
func Accept_encoding_lookup(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Accept_encoding_lookup_Validate(args); err != nil {
		return value.Null, err
	}

	lookup := value.Unwrap[*value.String](args[0])
	defaultValue := value.Unwrap[*value.String](args[1])
	encoding := value.Unwrap[*value.String](args[2])

	var encodings []string
	for _, v := range strings.Split(lookup.Value, ":") {
		encodings = append(encodings, v)
	}

	index := len(encodings)
	for _, v := range strings.Split(encoding.Value, ",") {
		v = strings.TrimSpace(v)
		if idx := strings.Index(v, ";"); idx != -1 {
			v = v[0:idx]
		}
		for i := range encodings {
			if encodings[i] == v {
				if i < index {
					index = i
				}
			}
		}
	}

	if index < len(encodings) {
		return &value.String{Value: encodings[index]}, nil
	}
	return defaultValue, nil
}
