package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

var _ [mldsa44.PublicKeySize - 1312]byte
var _ [1312 - mldsa44.PublicKeySize]byte

var _ [mldsa65.PublicKeySize - 1952]byte
var _ [1952 - mldsa65.PublicKeySize]byte

var _ [mldsa87.PublicKeySize - 2592]byte
var _ [2592 - mldsa87.PublicKeySize]byte

var _ [mldsa44.SignatureSize - 2420]byte
var _ [2420 - mldsa44.SignatureSize]byte

var _ [mldsa65.SignatureSize - 3309]byte
var _ [3309 - mldsa65.SignatureSize]byte

var _ [mldsa87.SignatureSize - 4627]byte
var _ [4627 - mldsa87.SignatureSize]byte

func read(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func verify44(
	pkBytes []byte,
	msg []byte,
	ctx []byte,
	sig []byte,
) (bool, error) {
	var pk mldsa44.PublicKey

	if err := pk.UnmarshalBinary(
		pkBytes,
	); err != nil {
		return false, err
	}

	return mldsa44.Verify(
		&pk,
		msg,
		ctx,
		sig,
	), nil
}

func verify65(
	pkBytes []byte,
	msg []byte,
	ctx []byte,
	sig []byte,
) (bool, error) {
	var pk mldsa65.PublicKey

	if err := pk.UnmarshalBinary(
		pkBytes,
	); err != nil {
		return false, err
	}

	return mldsa65.Verify(
		&pk,
		msg,
		ctx,
		sig,
	), nil
}

func verify87(
	pkBytes []byte,
	msg []byte,
	ctx []byte,
	sig []byte,
) (bool, error) {
	var pk mldsa87.PublicKey

	if err := pk.UnmarshalBinary(
		pkBytes,
	); err != nil {
		return false, err
	}

	return mldsa87.Verify(
		&pk,
		msg,
		ctx,
		sig,
	), nil
}

func main() {
	if os.Getenv(
		"QSV_EXECUTE_CRYPTO",
	) != "YES" {
		fmt.Fprintln(
			os.Stderr,
			"STOP: QSV_EXECUTE_CRYPTO=YES required",
		)

		os.Exit(78)
	}

	if len(os.Args) != 7 {
		os.Exit(64)
	}

	alg := os.Args[1]

	expected, err := strconv.ParseBool(
		os.Args[6],
	)

	if err != nil {
		os.Exit(64)
	}

	pk, err := read(os.Args[2])
	if err != nil {
		os.Exit(70)
	}

	msg, err := read(os.Args[3])
	if err != nil {
		os.Exit(70)
	}

	ctx, err := read(os.Args[4])
	if err != nil {
		os.Exit(70)
	}

	sig, err := read(os.Args[5])
	if err != nil {
		os.Exit(70)
	}

	if len(ctx) > 255 {
		os.Exit(70)
	}

	var actual bool

	switch alg {

	case "ML-DSA-44":

		if len(pk) != mldsa44.PublicKeySize ||
			len(sig) != mldsa44.SignatureSize {
			os.Exit(70)
		}

		actual, err = verify44(
			pk,
			msg,
			ctx,
			sig,
		)

	case "ML-DSA-65":

		if len(pk) != mldsa65.PublicKeySize ||
			len(sig) != mldsa65.SignatureSize {
			os.Exit(70)
		}

		actual, err = verify65(
			pk,
			msg,
			ctx,
			sig,
		)

	case "ML-DSA-87":

		if len(pk) != mldsa87.PublicKeySize ||
			len(sig) != mldsa87.SignatureSize {
			os.Exit(70)
		}

		actual, err = verify87(
			pk,
			msg,
			ctx,
			sig,
		)

	default:
		os.Exit(64)
	}

	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"CIRCL_OPERATIONAL_ERROR=YES",
		)

		os.Exit(70)
	}

	fmt.Printf(
		"CIRCL_ACTUAL_VALID=%t\n",
		actual,
	)

	fmt.Printf(
		"CIRCL_EXPECTED_VALID=%t\n",
		expected,
	)

	if actual != expected {
		fmt.Fprintln(
			os.Stderr,
			"CIRCL_EXPECTATION_MATCH=NO",
		)

		os.Exit(1)
	}

	fmt.Println(
		"CIRCL_EXPECTATION_MATCH=YES",
	)
}
