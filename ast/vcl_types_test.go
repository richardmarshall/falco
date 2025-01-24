package ast

import (
	"testing"
)

func TestString(t *testing.T) {
	str := &String{
		Meta:  New(T, 0, comments("// This is comment"), comments("// This is comment")),
		Value: "basic string",
	}

	cases := []struct {
		offset  int
		expect  string
		heredoc string
	}{
		{0, `// This is comment "basic string" // This is comment`, ""},
		{4, `// This is comment {"basic string"} // This is comment`, ""},
		{8, `// This is comment {ab"basic string"ab} // This is comment`, "ab"},
	}

	for _, c := range cases {
		str.Token.Offset = c.offset
		str.Heredoc = c.heredoc
		assert(t, str.String(), c.expect)
	}
}
