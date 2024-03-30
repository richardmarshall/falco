// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"math"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Math_asinh_Name = "math.asinh"

var Math_asinh_ArgumentTypes = []value.Type{value.FloatType}

func Math_asinh_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Math_asinh_Name, 1, args)
	}
	args = shared.CoerceArguments(args, Math_asinh_ArgumentTypes)
	for i := range args {
		if args[i].Type() != Math_asinh_ArgumentTypes[i] {
			return errors.TypeMismatch(Math_asinh_Name, i+1, Math_asinh_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of math.asinh
// Arguments may be:
// - FLOAT
// Reference: https://developer.fastly.com/reference/vcl/functions/math-trig/math-asinh/
func Math_asinh(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Math_asinh_Validate(args); err != nil {
		return value.Null, err
	}

	x := value.Unwrap[*value.Float](args[0])
	switch {
	case x.IsNAN:
		return &value.Float{IsNAN: true}, nil
	case x.IsNegativeInf:
		return &value.Float{Value: x.Value}, nil
	case x.IsPositiveInf:
		return &value.Float{Value: x.Value}, nil
	case x.Value == 0:
		return &value.Float{Value: x.Value}, nil
	case shared.IsSubnormalFloat64(x.Value):
		ctx.FastlyError = &value.String{Value: "ERANGE"}
		return &value.Float{Value: x.Value}, nil
	default:
		return &value.Float{Value: math.Asinh(x.Value)}, nil
	}
}
