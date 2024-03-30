package operator

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Equal(left, right value.Value) (value.Value, error) {
	if left.IsLiteral() {
		return value.Null, errors.WithStack(
			fmt.Errorf("Could not use literal for equal operator of left hand"),
		)
	}

	switch left.Type() {
	case value.IntegerType:
		if right.Type() != value.IntegerType {
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		rv := value.Unwrap[*value.Integer](right)
		if lv.IsNAN || rv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		return &value.Boolean{Value: lv.Value == rv.Value}, nil
	case value.FloatType:
		if right.Type() != value.FloatType {
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		rv := value.Unwrap[*value.Float](right)
		if lv.IsNAN || rv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		return &value.Boolean{Value: lv.Value == rv.Value}, nil
	case value.StringType:
		if right.Type() != value.StringType {
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
		lv := value.Unwrap[*value.String](left)
		rv := value.Unwrap[*value.String](right)
		// IsNotSet string does not match all equal expression
		if lv.IsNotSet || rv.IsNotSet {
			return &value.Boolean{Value: false}, nil
		}
		return &value.Boolean{Value: lv.Value == rv.Value}, nil
	}
	if left.Type() != right.Type() {
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}

	return &value.Boolean{
		Value: left.String() == right.String(),
	}, nil
}

func NotEqual(left, right value.Value) (value.Value, error) {
	b, err := Equal(left, right)
	if err != nil {
		return b, err
	}
	return &value.Boolean{
		Value: !value.Unwrap[*value.Boolean](b).Value,
	}, nil
}

func GreaterThan(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal of left hand"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value > int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value > float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value > float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) > rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: float64(lv.Value/time.Second) > rv.Value,
			}, nil
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value > rv.Value,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func LessThan(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value < int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value < float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value < float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) < rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)

			return &value.Boolean{
				Value: float64(lv.Value/time.Second) < rv.Value,
			}, nil
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value < rv.Value,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func GreaterThanEqual(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value >= int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value >= float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value >= float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) >= rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: float64(lv.Value/time.Second) >= rv.Value,
			}, nil
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value >= rv.Value,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func LessThanEqual(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.IntegerType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Integer](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value <= int64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.FloatType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left FLOAT type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.Float](left)
		if lv.IsNAN {
			return &value.Boolean{Value: false}, nil
		}
		switch right.Type() {
		case value.IntegerType:
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value <= float64(rv.Value),
			}, nil
		case value.FloatType:
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		case value.RTimeType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right RTIME type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value <= float64(rv.Value/time.Second),
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.RTimeType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left RTIME type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.RTime](left)
		switch right.Type() {
		case value.IntegerType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right INTEGER type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Integer](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: int64(lv.Value/time.Second) <= rv.Value,
			}, nil
		case value.FloatType:
			if right.IsLiteral() {
				return value.Null, errors.WithStack(
					fmt.Errorf("Right FLOAT type could not be a literal"),
				)
			}
			rv := value.Unwrap[*value.Float](right)
			if rv.IsNAN {
				return &value.Boolean{Value: false}, nil
			}

			return &value.Boolean{
				Value: float64(lv.Value/time.Second) <= rv.Value,
			}, nil
		case value.RTimeType:
			rv := value.Unwrap[*value.RTime](right)

			return &value.Boolean{
				Value: lv.Value <= rv.Value,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func Regex(ctx *context.Context, left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.StringType:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Left String type could not be a literal"),
			)
		}
		lv := value.Unwrap[*value.String](left)
		switch right.Type() {
		case value.StringType:
			rv := value.Unwrap[*value.String](right)
			re, err := regexp.Compile(rv.Value)
			if err != nil {
				return value.Null, errors.WithStack(
					fmt.Errorf("Failed to compile regular expression from string %s", rv.Value),
				)
			}
			if matches := re.FindStringSubmatch(lv.Value); matches != nil {
				for j, m := range matches {
					ctx.RegexMatchedValues[fmt.Sprint(j)] = &value.String{Value: m}
				}
				return &value.Boolean{Value: true}, nil
			}
			return &value.Boolean{Value: false}, nil
		case value.AclType:
			rv := value.Unwrap[*value.Acl](right)
			ip := net.ParseIP(lv.Value)
			if ip == nil {
				return value.Null, errors.WithStack(
					fmt.Errorf("Failed to parse IP from string %s", lv.Value),
				)
			}
			res, err := matchesAcl(*rv, ip)
			if err != nil {
				return value.Null, errors.WithStack(err)
			}
			return &value.Boolean{
				Value: res,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	case value.IpType:
		lv := value.Unwrap[*value.IP](left)
		switch right.Type() {
		case value.AclType:
			rv := value.Unwrap[*value.Acl](right)
			res, err := matchesAcl(*rv, lv.Value)
			if err != nil {
				return value.Null, errors.WithStack(err)
			}
			return &value.Boolean{
				Value: res,
			}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
			)
		}
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Invalid type comparison %s and %s", left.Type(), right.Type()),
		)
	}
}

func matchesAcl(acl value.Acl, ip net.IP) (bool, error) {
	for _, entry := range acl.Value.CIDRs {
		var mask int64 = 32
		if entry.Mask != nil {
			mask = entry.Mask.Value
		}

		cidr := fmt.Sprintf("%s/%d", entry.IP.Value, mask)
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return false, fmt.Errorf("Failed to parse CIDR %s", cidr)
		}
		if ipnet.Contains(ip) {
			return true, nil
		} else if entry.Inverse != nil && entry.Inverse.Value {
			return true, nil
		}
	}
	return false, nil
}

func NotRegex(ctx *context.Context, left, right value.Value) (value.Value, error) {
	b, err := Regex(ctx, left, right)
	if err != nil {
		return b, err
	}
	return &value.Boolean{
		Value: !value.Unwrap[*value.Boolean](b).Value,
	}, nil
}

func LogicalAnd(left, right value.Value) (value.Value, error) {
	var lv, rv bool

	switch left.Type() {
	case value.BooleanType:
		lv = value.Unwrap[*value.Boolean](left).Value
	case value.StringType:
		str := value.Unwrap[*value.String](left)
		// Could not use literal string in expression
		if str.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Logical AND operator: Could not use string literal in left expression, value is %s", str.Value),
			)
		}
		lv = str.Value != ""
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: left type must be falsy type, got %s", left.Type()),
		)
	}

	switch right.Type() {
	case value.BooleanType:
		rv = value.Unwrap[*value.Boolean](right).Value
	case value.StringType:
		str := value.Unwrap[*value.String](right)
		// Could not use literal string in expression
		if str.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Logical AND operator: Could not use string literal in right expression, value is %s", str.Value),
			)
		}
		rv = str.Value != ""
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Logical AND operator: right type must be falsy type, got %s", right.Type()),
		)
	}

	return &value.Boolean{Value: lv && rv}, nil
}

func LogicalOr(left, right value.Value) (value.Value, error) {
	var lv, rv bool

	switch left.Type() {
	case value.BooleanType:
		lv = value.Unwrap[*value.Boolean](left).Value
	case value.StringType:
		str := value.Unwrap[*value.String](left)
		// Could not use literal string in expression
		if str.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Logical OR operator: Could not use string literal in left expression, value is %s", str.Value),
			)
		}
		lv = str.Value != ""
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Logical OR operator: left type must be falsy type, got %s", left.Type()),
		)
	}

	switch right.Type() {
	case value.BooleanType:
		rv = value.Unwrap[*value.Boolean](right).Value
	case value.StringType:
		str := value.Unwrap[*value.String](right)
		// Could not use literal string in expression
		if str.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("Logical OR operator: Could not use string literal in right expression, value is %s", str.Value),
			)
		}
		rv = str.Value != ""
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Logical OR operator: right type must be falsy type, got %s", right.Type()),
		)
	}

	return &value.Boolean{Value: lv || rv}, nil
}

func Concat(left, right value.Value) (value.Value, error) {
	switch left.Type() {
	case value.AclType, value.IdentType:
		return value.Null, errors.WithStack(
			fmt.Errorf("%s type could not use for left concatenation expression", left.Type()),
		)
	case value.StringType, value.BooleanType:
		break
	default:
		if left.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("%s type could not use as literal for left concatenation expression", left.Type()),
			)
		}
	}
	switch right.Type() {
	case value.AclType, value.IdentType:
		return value.Null, errors.WithStack(
			fmt.Errorf("%s type could not unse for right concatenation expression", right.Type()),
		)
	case value.StringType, value.BooleanType:
		break
	default:
		if right.IsLiteral() {
			return value.Null, errors.WithStack(
				fmt.Errorf("%s type could not use as literal for right concatenation expression", right.Type()),
			)
		}
	}

	// Special case to handle querystring.filter*() requirement that concat
	// expression values be literal strings.
	if !left.IsLiteral() && right.String() == "\xFF" {
		return value.Null, errors.WithStack(
			fmt.Errorf(""),
		)
	}

	return &value.String{
		Value: left.String() + right.String(),
	}, nil
}
