// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/function/shared"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Digest_hmac_sha1_Name = "digest.hmac_sha1"

var Digest_hmac_sha1_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Digest_hmac_sha1_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Digest_hmac_sha1_Name, 2, args)
	}
	args = shared.CoerceArguments(args, Digest_hmac_sha1_ArgumentTypes)
	for i := range args {
		if args[i].Type() != Digest_hmac_sha1_ArgumentTypes[i] {
			return errors.TypeMismatch(Digest_hmac_sha1_Name, i+1, Digest_hmac_sha1_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of digest.hmac_sha1
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/cryptographic/digest-hmac-sha1/
func Digest_hmac_sha1(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Digest_hmac_sha1_Validate(args); err != nil {
		return value.Null, err
	}

	key := value.Unwrap[*value.String](args[0])
	input := value.Unwrap[*value.String](args[1])
	mac := hmac.New(sha1.New, []byte(key.Value))
	mac.Write([]byte(input.Value))

	return &value.String{
		Value: hex.EncodeToString(mac.Sum(nil)),
	}, nil
}
