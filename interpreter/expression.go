package interpreter

import (
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/function"
	"github.com/ysugimoto/falco/interpreter/operator"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/types"
)

func (i *Interpreter) IdentValue(val string, flags uint8) (value.Value, error) {
	// Extra lookups identity - call additional ident finder if defined
	// This feature is implemented for testing, typically we do not use for interpreter working
	if i.IdentResolver != nil {
		if v := i.IdentResolver(val); v != nil {
			return v, nil
		}
	}

	if v, ok := i.ctx.Backends[val]; ok {
		return v, nil
	} else if v, ok := i.ctx.Acls[val]; ok {
		return v, nil
	} else if _, ok := i.ctx.Tables[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if _, ok := i.ctx.Gotos[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if _, ok := i.ctx.Penaltyboxes[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if _, ok := i.ctx.Ratecounters[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if strings.HasPrefix(val, "var.") {
		if v, err := i.localVars.Get(val); err != nil {
			return value.Null, errors.WithStack(err)
		} else {
			return v, nil
		}
	} else if v, err := i.vars.Get(i.ctx.Scope, val); err != nil {
		if flags&CONDITIONS == CONDITIONS {
			return value.Null, nil
		} else {
			return value.Null, errors.WithStack(err)
		}
	} else {
		return v, nil
	}
}

const (
	DEFAULT    uint8 = 0
	CONDITIONS       = 1 << iota
	NOCONCAT
)

// Evaluate expression
// flags uint8ean is special flag for evaluating expression,
// used for if condition, parenthesis wrapped expression.
// On if condition, prefix expression could use "!" prefix operator for null value.
//
// For example:
//
//	flags: true  -> if (!req.http.Foo) { ... } // Valid, req.http.Foo is nullable string but can be inverse as false
//	flags: false -> set var.bool = (!req.http.Foo); // Complicated but valid, "!" prefix operator could  use for right expression
//	flags: false -> set var.bool = !req.http.Foo;   // Invalid, bare "!" prefix operator could not use for right expression
func (i *Interpreter) ProcessExpression(exp ast.Expression, flags uint8) (value.Value, error) {
	switch t := exp.(type) {
	// Underlying VCL type expressions
	case *ast.Ident:
		return i.IdentValue(t.Value, flags)
	case *ast.IP:
		return &value.IP{Value: net.ParseIP(t.Value), Literal: true}, nil
	case *ast.Boolean:
		return &value.Boolean{Value: t.Value, Literal: true}, nil
	case *ast.Integer:
		return &value.Integer{Value: t.Value, Literal: true}, nil
	case *ast.String:
		return &value.String{Value: t.Value, Literal: true}, nil
	case *ast.Float:
		return &value.Float{Value: t.Value, Literal: true}, nil
	case *ast.RTime:
		var val time.Duration
		var err error
		switch {
		case strings.HasSuffix(t.Value, "d"):
			num := strings.TrimSuffix(t.Value, "d")
			val, err = time.ParseDuration(num + "h")
			if err != nil {
				return nil, exception.Runtime(&exp.GetMeta().Token, "Failed to parse duration: %s", err)
			}
			val *= 24
		case strings.HasSuffix(t.Value, "y"):
			num := strings.TrimSuffix(t.Value, "y")
			val, err = time.ParseDuration(num + "h")
			if err != nil {
				return nil, exception.Runtime(&exp.GetMeta().Token, "Failed to parse duration: %s", err)
			}
			val *= 24 * 365
		default:
			val, err = time.ParseDuration(t.Value)
			if err != nil {
				return nil, exception.Runtime(&exp.GetMeta().Token, "Failed to parse duration: %s", err)
			}
		}
		return &value.RTime{Value: val, Literal: true}, nil

	// Combined expressions
	case *ast.PrefixExpression:
		return i.ProcessPrefixExpression(t, flags)
	case *ast.GroupedExpression:
		return i.ProcessGroupedExpression(t)
	case *ast.InfixExpression:
		return i.ProcessInfixExpression(t, flags)
	case *ast.IfExpression:
		return i.ProcessIfExpression(t)
	case *ast.FunctionCallExpression:
		return i.ProcessFunctionCallExpression(t, flags)
	default:
		return value.Null, exception.Runtime(&exp.GetMeta().Token, "Undefined expression found")
	}
}

func (i *Interpreter) ProcessPrefixExpression(exp *ast.PrefixExpression, flags uint8) (value.Value, error) {
	v, err := i.ProcessExpression(exp.Right, flags)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}

	switch exp.Operator {
	case "!":
		switch t := v.(type) {
		case *value.Boolean:
			return &value.Boolean{Value: !t.Value}, nil
		case *value.String:
			// If CONDITION flag is set, STRING could be converted to BOOL
			if flags&CONDITIONS != CONDITIONS {
				return value.Null, errors.WithStack(
					exception.Runtime(&exp.GetMeta().Token, `Unexpected "!" prefix operator for %v`, v),
				)
			}
			return &value.Boolean{Value: t.IsNotSet}, nil
		default:
			return value.Null, errors.WithStack(
				exception.Runtime(&exp.GetMeta().Token, `Unexpected "!" prefix operator for %v`, v),
			)
		}
	case "-":
		switch t := v.(type) {
		case *value.Integer:
			t.Value = -t.Value
			return t, nil
		case *value.Float:
			t.Value = -t.Value
			return t, nil
		case *value.RTime:
			t.Value = -t.Value
			return t, nil
		default:
			return value.Null, errors.WithStack(
				exception.Runtime(&exp.GetMeta().Token, `Unexpected "-" prefix operator for %v`, v),
			)
		}
	case "+":
		// I'm wondering what calculate to?
		return v, nil
	default:
		return value.Null, errors.WithStack(
			exception.Runtime(&exp.GetMeta().Token, "Unexpected prefix operator: %s", exp.Operator),
		)
	}
}

func (i *Interpreter) ProcessGroupedExpression(exp *ast.GroupedExpression) (value.Value, error) {
	v, err := i.ProcessExpression(exp.Right, CONDITIONS)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	return v, nil
}

func (i *Interpreter) ProcessIfExpression(exp *ast.IfExpression) (value.Value, error) {
	cond, err := i.ProcessExpression(exp.Condition, CONDITIONS)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}

	switch t := cond.(type) {
	case *value.Boolean:
		if t.Value {
			return i.ProcessExpression(exp.Consequence, DEFAULT)
		}
	case *value.String:
		if !t.IsNotSet {
			return i.ProcessExpression(exp.Consequence, DEFAULT)
		}
	default:
		if cond == value.Null {
			return i.ProcessExpression(exp.Alternative, DEFAULT)
		}
		return value.Null, exception.Runtime(&exp.GetMeta().Token, "If condition returns not boolean")
	}

	return i.ProcessExpression(exp.Alternative, DEFAULT)
}

func (i *Interpreter) ProcessFunctionCallExpression(exp *ast.FunctionCallExpression, flags uint8) (value.Value, error) {
	if sub, ok := i.ctx.SubroutineFunctions[exp.Function.Value]; ok {
		if len(exp.Arguments) > 0 {
			return value.Null, exception.Runtime(
				&exp.GetMeta().Token,
				"Function subroutine %s could not accept any arguments",
				exp.Function.Value,
			)
		}
		if _, ok := types.ValueTypeMap[sub.ReturnType.Value]; !ok {
			return value.Null, exception.Runtime(
				&sub.GetMeta().Token,
				"subroutine %s has invalid return type %s",
				sub.Name,
				sub.ReturnType,
			)
		}
		// Functional subroutine may change status
		v, _, err := i.ProcessFunctionSubroutine(sub, DebugPass)
		if err != nil {
			return v, errors.WithStack(err)
		}
		return v, nil
	}
	fn, err := function.Exists(i.ctx.Scope, exp.Function.Value)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	args := make([]value.Value, len(exp.Arguments))
	for j := range exp.Arguments {
		if fn.IsIdentArgument(j) {
			// If function accepts ID type, pass the string as Ident value without processing expression.
			// This is because some function uses collection value like req.http.Cookie as ID type,
			// But the processor passes *value.String as primitive value normally.
			// In order to treat collection value inside, ensure ident argument is treated as correspond types.
			if ident, ok := exp.Arguments[j].(*ast.Ident); ok {
				args[j] = &value.Ident{Value: ident.Value}
			} else {
				return value.Null, errors.WithStack(
					exception.Runtime(
						&exp.Arguments[j].GetMeta().Token,
						"Function %s of %d argument must be an Ident", exp.Function.Value, j,
					),
				)
			}
		} else {
			a, err := i.ProcessExpression(exp.Arguments[j], flags)
			if err != nil {
				return value.Null, errors.WithStack(err)
			}
			args[j] = a
		}
	}
	return fn.Call(i.ctx, args...)
}

func (i *Interpreter) ProcessInfixExpression(exp *ast.InfixExpression, flags uint8) (value.Value, error) {
	left, err := i.ProcessExpression(exp.Left, flags)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	right, err := i.ProcessExpression(exp.Right, flags)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}

	var result value.Value
	var opErr error

	switch exp.Operator {
	case "==":
		result, opErr = operator.Equal(left, right)
	case "!=":
		result, opErr = operator.NotEqual(left, right)
	case ">":
		result, opErr = operator.GreaterThan(left, right)
	case "<":
		result, opErr = operator.LessThan(left, right)
	case ">=":
		result, opErr = operator.GreaterThanEqual(left, right)
	case "<=":
		result, opErr = operator.LessThanEqual(left, right)
	case "~":
		result, opErr = operator.Regex(i.ctx, left, right)
	case "!~":
		result, opErr = operator.NotRegex(i.ctx, left, right)
	case "||":
		result, opErr = operator.LogicalOr(left, right)
	case "&&":
		result, opErr = operator.LogicalAnd(left, right)
	// "+" means string concatenation
	case "+":
		if flags&NOCONCAT == NOCONCAT {
			return value.Null, errors.WithStack(
				exception.Runtime(&exp.GetMeta().Token, "Unexpected infix operator: %s", exp.Operator),
			)
		}
		result, opErr = operator.Concat(left, right)
	default:
		return value.Null, errors.WithStack(
			exception.Runtime(&exp.GetMeta().Token, "Unexpected infix operator: %s", exp.Operator),
		)
	}

	if opErr != nil {
		return value.Null, errors.WithStack(
			exception.Runtime(&exp.GetMeta().Token, opErr.Error()),
		)
	}

	return result, nil
}
