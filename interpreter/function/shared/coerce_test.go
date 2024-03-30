package shared

import (
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/value"
)

var (
	coerceAllTypes = []value.Value{
		&value.Acl{Value: &ast.AclDeclaration{}},
		&value.Backend{
			Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "_backend_"}},
		},
		&value.Boolean{Value: true},
		&value.Boolean{Value: true, Literal: true},
		&value.Float{Value: 1.5},
		&value.Float{Value: 1.5, Literal: true},
		&value.Ident{Value: "req"},
		&value.Integer{Value: 1},
		&value.Integer{Value: 1, Literal: true},
		&value.IP{Value: net.ParseIP("127.0.0.1")},
		&value.RTime{Value: time.Minute},
		&value.RTime{Value: time.Minute, Literal: true},
		&value.String{Value: "a"},
		&value.String{Value: "a", Literal: true},
		&value.Time{},
	}

	coerceFloatExpect = []value.Value{
		&value.Acl{Value: &ast.AclDeclaration{}},
		&value.Backend{
			Value: &ast.BackendDeclaration{Name: &ast.Ident{Value: "_backend_"}},
		},
		&value.Boolean{Value: true},
		&value.Boolean{Value: true, Literal: true},
		&value.Float{Value: 1.5},
		&value.Float{Value: 1.5, Literal: true},
		&value.Ident{Value: "req"},
		&value.Float{Value: 1},
		&value.Float{Value: 1},
		&value.IP{Value: net.ParseIP("127.0.0.1")},
		&value.RTime{Value: time.Minute},
		&value.RTime{Value: time.Minute, Literal: true},
		&value.String{Value: "a"},
		&value.String{Value: "a", Literal: true},
		&value.Time{},
	}

	coerceStringExpect = []value.Value{
		&value.Acl{Value: &ast.AclDeclaration{}},
		&value.String{Value: "_backend_"},
		&value.String{Value: "1"},
		&value.Boolean{Value: true, Literal: true},
		&value.String{Value: "1.500"},
		&value.Float{Value: 1.5, Literal: true},
		&value.Ident{Value: "req"},
		&value.String{Value: "1"},
		&value.Integer{Value: 1, Literal: true},
		&value.String{Value: "127.0.0.1"},
		&value.String{Value: "60.000"},
		&value.RTime{Value: time.Minute, Literal: true},
		&value.String{Value: "a"},
		&value.String{Value: "a", Literal: true},
		&value.String{Value: "Mon, 01 Jan 0001 00:00:00 GMT"},
	}
)

func sliceN[T any](n int, c T) []T {
	r := make([]T, n)
	for i := range r {
		r[i] = c
	}
	return r
}

func TestCoerceArguments(t *testing.T) {
	tests := []struct {
		name   string
		args   []value.Value
		types  []value.Type
		expect []value.Value
	}{
		{name: "No arguments", types: []value.Type{}, args: []value.Value{}, expect: []value.Value{}},
		{ // too many passed values ignored
			name:   "Too many arguments",
			types:  []value.Type{value.StringType},
			args:   []value.Value{&value.Integer{Value: 1}, &value.Float{Value: 1.5}},
			expect: []value.Value{&value.Integer{Value: 1}, &value.Float{Value: 1.5}},
		},
		{ // fewer values than arguments (optional arguments)
			name:   "Optional Arguments",
			types:  []value.Type{value.StringType, value.IntegerType, value.BooleanType},
			args:   []value.Value{&value.String{Value: "a"}, &value.Integer{Value: 1}},
			expect: []value.Value{&value.String{Value: "a"}, &value.Integer{Value: 1}},
		},
		//
		{name: "ACL", types: sliceN(len(coerceAllTypes), value.AclType), args: coerceAllTypes, expect: coerceAllTypes},
		{name: "BACKEND", types: sliceN(len(coerceAllTypes), value.BackendType), args: coerceAllTypes, expect: coerceAllTypes},
		{name: "BOOL", types: sliceN(len(coerceAllTypes), value.BooleanType), args: coerceAllTypes, expect: coerceAllTypes},
		{name: "FLOAT", types: sliceN(len(coerceAllTypes), value.FloatType), args: coerceAllTypes, expect: coerceFloatExpect},
		{name: "ID", types: sliceN(len(coerceAllTypes), value.IdentType), args: coerceAllTypes, expect: coerceAllTypes},
		{name: "Integer", types: sliceN(len(coerceAllTypes), value.IntegerType), args: coerceAllTypes, expect: coerceAllTypes},
		{name: "IP", types: sliceN(len(coerceAllTypes), value.IpType), args: coerceAllTypes, expect: coerceAllTypes},
		{name: "RTIME", types: sliceN(len(coerceAllTypes), value.RTimeType), args: coerceAllTypes, expect: coerceAllTypes},
		{name: "STRING", types: sliceN(len(coerceAllTypes), value.StringType), args: coerceAllTypes, expect: coerceStringExpect},
		{name: "TIME", types: sliceN(len(coerceAllTypes), value.TimeType), args: coerceAllTypes, expect: coerceAllTypes},
	}

	for _, tt := range tests {
		coerced := CoerceArguments(tt.args, tt.types)
		if diff := cmp.Diff(tt.expect, coerced); diff != "" {
			t.Errorf("[%s] Unexpected return value, diff=%s", tt.name, diff)
		}
	}
}

func TestCoerceArgumentsVariadic(t *testing.T) {
	tests := []struct {
		name   string
		types  []value.Type
		args   []value.Value
		expect []value.Value
	}{
		{name: "No arguments", types: []value.Type{}, args: []value.Value{}, expect: []value.Value{}},
		{name: "ACL", types: []value.Type{value.AclType}, args: coerceAllTypes, expect: coerceAllTypes},
		{name: "BACKEND", types: []value.Type{value.BackendType}, args: coerceAllTypes, expect: coerceAllTypes},
		{name: "BOOL", types: []value.Type{value.BooleanType}, args: coerceAllTypes, expect: coerceAllTypes},
		{name: "FLOAT", types: []value.Type{value.FloatType}, args: coerceAllTypes, expect: coerceFloatExpect},
		{name: "ID", types: []value.Type{value.IdentType}, args: coerceAllTypes, expect: coerceAllTypes},
		{name: "INTEGER", types: []value.Type{value.IntegerType}, args: coerceAllTypes, expect: coerceAllTypes},
		{name: "IP", types: []value.Type{value.IpType}, args: coerceAllTypes, expect: coerceAllTypes},
		{name: "RTIME", types: []value.Type{value.RTimeType}, args: coerceAllTypes, expect: coerceAllTypes},
		{name: "STRING", types: []value.Type{value.StringType}, args: coerceAllTypes, expect: coerceStringExpect},
		{name: "TIME", types: []value.Type{value.TimeType}, args: coerceAllTypes, expect: coerceAllTypes},
	}

	for _, tt := range tests {
		coerced := CoerceArgumentsVariatic(tt.args, tt.types)
		if diff := cmp.Diff(tt.expect, coerced); diff != "" {
			t.Errorf("[%s] Unexpected return value, diff=%s", tt.name, diff)
		}
	}
}
