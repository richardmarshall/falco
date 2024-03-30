// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Std_collect_Name = "std.collect"

var Std_collect_ArgumentTypes = []value.Type{value.IdentType, value.StringType}

func Std_collect_Validate(args []value.Value) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.ArgumentNotInRange(Std_collect_Name, 1, 2, args)
	}
	args = shared.CoerceArguments(args, Std_collect_ArgumentTypes)
	for i := range args {
		if args[i].Type() != Std_collect_ArgumentTypes[i] {
			return errors.TypeMismatch(Std_collect_Name, i+1, Std_collect_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of std.collect
// Arguments may be:
// - ID
// - ID, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/miscellaneous/std-collect/
func Std_collect(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Std_collect_Validate(args); err != nil {
		return value.Null, err
	}

	// TODO: std.collection has no effect because Golang's HTTP header is automatically collected
	// ident := value.Unwrap[*value.Ident](args[0])
	// sep := ","
	// if len(args) > 1 {
	// 	sep = value.Unwrap[*value.String](args[1]).Value
	// }
	//
	// switch {
	// case strings.HasPrefix(ident.Value, "req.http."):
	// 	name := strings.TrimPrefix(ident.Value, "req.http.")
	// 	value := ctx.Request.Header.Values(name)
	// 	ctx.Request.Header.Set(name, strings.Join(value, sep))
	// case strings.HasPrefix(ident.Value, "bereq.http"):
	// 	name := strings.TrimPrefix(ident.Value, "bereq.http.")
	// 	value := ctx.BackendRequest.Header.Values(name)
	// 	ctx.BackendRequest.Header.Set(name, strings.Join(value, sep))
	// case strings.HasPrefix(ident.Value, "beresp.http"):
	// 	name := strings.TrimPrefix(ident.Value, "beresp.http.")
	// 	value := ctx.BackendResponse.Header.Values(name)
	// 	ctx.Request.Header.Set(name, strings.Join(value, sep))
	// case strings.HasPrefix(ident.Value, "resp.http"):
	// 	name := strings.TrimPrefix(ident.Value, "resp.http.")
	// 	value := ctx.BackendResponse.Header.Values(name)
	// 	ctx.BackendResponse.Header.Set(name, strings.Join(value, sep))
	// }

	return value.Null, nil
}
