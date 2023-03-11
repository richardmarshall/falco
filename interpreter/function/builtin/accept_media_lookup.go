// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Accept_media_lookup_Name = "accept.media_lookup"

var Accept_media_lookup_ArgumentTypes = []value.Type{value.StringType, value.StringType, value.StringType, value.StringType}

func Accept_media_lookup_Validate(args []value.Value) error {
	if len(args) != 4 {
		return errors.ArgumentNotEnough(Accept_media_lookup_Name, 4, args)
	}
	for i := range args {
		if args[i].Type() != Accept_media_lookup_ArgumentTypes[i] {
			return errors.TypeMismatch(Accept_media_lookup_Name, i+1, Accept_media_lookup_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of accept.media_lookup
// Arguments may be:
// - STRING, STRING, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/content-negotiation/accept-media-lookup/
func Accept_media_lookup(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Accept_media_lookup_Validate(args); err != nil {
		return value.Null, err
	}

	lookup := value.Unwrap[*value.String](args[0])
	defaultValue := value.Unwrap[*value.String](args[1])
	pattern := value.Unwrap[*value.String](args[2])
	accept := value.Unwrap[*value.String](args[3])

	// Third argument MUST be a literal, could not variable
	if !pattern.IsLiteral() {
		return value.Null, errors.New(Accept_media_lookup_Name, "Third argument must be a literal")
	}

	mediaTypes := make(map[string]string)
	for _, v := range strings.Split(lookup.Value, ":") {
		mediaTypes[v] = v
	}

	patterns := make(map[string]string)
	for _, v := range strings.Split(pattern.Value, ":") {
		// Duplicate media types are not allowed among the first three arguments.
		if _, ok := mediaTypes[v]; ok {
			return value.Null, errors.New(Accept_media_lookup_Name, "Third argument media must not duplicate in first argument")
		}
		patterns[v] = v

		// Also add to group pattern
		if idx := strings.Index(v, "/"); idx != -1 {
			patterns[v[0:idx]+"/*"] = v
		}
	}

	for _, v := range strings.Split(accept.Value, ",") {
		v = strings.TrimSpace(v)
		if idx := strings.Index(v, ";"); idx != -1 {
			v = v[0:idx]
		}
		if m, ok := mediaTypes[v]; ok {
			return &value.String{Value: m}, nil
		} else if m, ok := patterns[v]; ok {
			return &value.String{Value: m}, nil
		} else if v == "*/*" {
			return defaultValue, nil
		}
	}

	return &value.String{Value: ""}, nil
}
