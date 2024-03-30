// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Digest_base64url_nopad_decode_Name = "digest.base64url_nopad_decode"

var Digest_base64url_nopad_decode_ArgumentTypes = []value.Type{value.StringType}

func Digest_base64url_nopad_decode_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Digest_base64url_nopad_decode_Name, 1, args)
	}
	args = shared.CoerceArguments(args, Digest_base64url_nopad_decode_ArgumentTypes)
	for i := range args {
		if args[i].Type() != Digest_base64url_nopad_decode_ArgumentTypes[i] {
			return errors.TypeMismatch(Digest_base64url_nopad_decode_Name, i+1, Digest_base64url_nopad_decode_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of digest.base64url_nopad_decode
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-base64url-nopad-decode/
func Digest_base64url_nopad_decode(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Digest_base64url_nopad_decode_Validate(args); err != nil {
		return value.Null, err
	}

	input := value.Unwrap[*value.String](args[0])
	removed := Digest_base64url_nopad_decode_removeInvalidCharacters(input.Value)
	dec, _ := base64.RawURLEncoding.DecodeString(removed)

	return &value.String{Value: string(terminateNullByte(dec))}, nil
}

func Digest_base64url_nopad_decode_removeInvalidCharacters(input string) string {
	removed := new(bytes.Buffer)
	r := bufio.NewReader(strings.NewReader(input))

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		switch {
		case b >= 0x41 && b <= 0x5A: // A-Z
			removed.WriteByte(b)
		case b >= 0x61 && b <= 0x7A: // a-z
			removed.WriteByte(b)
		case b >= 0x31 && b <= 0x39: // 0-9
			removed.WriteByte(b)
		case b == 0x2B: // + should replace to -
			removed.WriteByte(0x2D)
		case b == 0x2F: // / should replace to _
			removed.WriteByte(0x5F)
		case b == 0x2D || b == 0x5F: // + or /
			removed.WriteByte(b)
		default:
			// Note: the "=" sign also treats as invalid character
			// Invalid characters, skip it
		}
	}

	return removed.String()
}
