// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"math"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Math_acosh_Name = "math.acosh"

var Math_acosh_ArgumentTypes = []value.Type{value.FloatType}

func Math_acosh_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Math_acosh_Name, 1, args)
	}
	args = shared.CoerceArguments(args, Math_acosh_ArgumentTypes)
	for i := range args {
		if args[i].Type() != Math_acosh_ArgumentTypes[i] {
			return errors.TypeMismatch(Math_acosh_Name, i+1, Math_acosh_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of math.acosh
// Arguments may be:
// - FLOAT
// Reference: https://developer.fastly.com/reference/vcl/functions/math-trig/math-acosh/
func Math_acosh(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Math_acosh_Validate(args); err != nil {
		return value.Null, err
	}

	x := value.Unwrap[*value.Float](args[0])
	switch {
	case x.IsNAN:
		return &value.Float{IsNAN: true}, nil
	case x.IsNegativeInf:
		ctx.FastlyError = &value.String{Value: "EDOM"}
		return &value.Float{IsNAN: true}, nil
	case x.IsPositiveInf:
		return &value.Float{IsPositiveInf: true}, nil
	case x.Value == 1.0:
		return &value.Float{Value: 0}, nil
	case x.Value < 1.0:
		ctx.FastlyError = &value.String{Value: "EDOM"}
		return &value.Float{IsNAN: true}, nil
	default:
		return &value.Float{Value: math.Acosh(x.Value)}, nil
	}
}
