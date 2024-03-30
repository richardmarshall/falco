// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Table_contains_Name = "table.contains"

var Table_contains_ArgumentTypes = []value.Type{value.IdentType, value.StringType}

func Table_contains_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Table_contains_Name, 2, args)
	}
	args = shared.CoerceArguments(args, Table_contains_ArgumentTypes)
	for i := range args {
		if args[i].Type() != Table_contains_ArgumentTypes[i] {
			return errors.TypeMismatch(Table_contains_Name, i+1, Table_contains_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of table.contains
// Arguments may be:
// - TABLE, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/table/table-contains/
func Table_contains(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Table_contains_Validate(args); err != nil {
		return value.Null, err
	}

	id := value.Unwrap[*value.Ident](args[0]).Value
	key := value.Unwrap[*value.String](args[1]).Value

	table, ok := ctx.Tables[id]
	if !ok {
		return &value.Boolean{Value: false}, errors.New(Table_contains_Name,
			"table %d does not exist", id,
		)
	}

	for _, prop := range table.Properties {
		if prop.Key.Value == key {
			return &value.Boolean{Value: true}, nil
		}
	}
	return &value.Boolean{Value: false}, nil
}
