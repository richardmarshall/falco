package shared

import (
	"github.com/ysugimoto/falco/interpreter/value"
)

// Run type coercion for each value / type pair.
func CoerceArguments(args []value.Value, types []value.Type) []value.Value {
	if len(args) > len(types) {
		return args
	}
	coerced := make([]value.Value, len(args))
	for i := range args {
		coerced[i] = coerceArgument(args[i], types[i])
	}
	return coerced
}

// Run type coercion for each value / type pair with the last type being used
// for any arguments that extend beyond the type list length. Used to support
// variadic functions. eg header.filter.
func CoerceArgumentsVariatic(args []value.Value, types []value.Type) []value.Value {
	if len(types) == 0 {
		return args
	}
	coerced := make([]value.Value, len(args))
	for i := range args {
		y := i
		if i >= len(types) {
			y = len(types) - 1
		}
		coerced[i] = coerceArgument(args[i], types[y])
	}
	return coerced
}

func coerceArgument(arg value.Value, t value.Type) value.Value {
	switch t {
	case value.StringType:
		return stringArgument(arg)
	case value.FloatType:
		return floatArgument(arg)
	}
	return arg
}

// Non-literal values of all types except ID and ACL are coerced into a string
// when passed as a string argument.
func stringArgument(v value.Value) value.Value {
	if s, ok := v.(*value.String); ok {
		return s
	}
	// ID / ACL types can't be coerced into STRING
	switch v.Type() {
	case value.IdentType, value.AclType:
		return v
	}
	// Non-string literals are not coerced. With the exception of the bool type.
	if v.Type() != value.BooleanType && v.IsLiteral() {
		return v
	}
	return &value.String{Value: v.String()}
}

// Integer values, including literals, are coerced into a float when passed as
// a float argument.
func floatArgument(v value.Value) value.Value {
	if f, ok := v.(*value.Float); ok {
		return f
	}
	if i, ok := v.(*value.Integer); ok {
		return &value.Float{Value: float64(i.Value)}
	}
	return v
}
