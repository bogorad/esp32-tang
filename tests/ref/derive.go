// Independent reference for the seed -> key derivation (HKDF-SHA256 with
// rejection sampling). Uses only the Go standard library (Go 1.24+). Not part
// of `make test`; it is how the known-answer values in test_seed.cpp were
// cross-checked.
//
//	go run tests/ref/derive.go <seed-hex>
package main

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func derive(prk []byte, role string) []byte {
	n := elliptic.P256().Params().N
	for ctr := 0; ctr < 256; ctr++ {
		info := "esp32-tang/v1/" + role + "\x00" + string([]byte{byte(ctr)})
		okm, err := hkdf.Expand(sha256.New, prk, info, 32)
		if err != nil {
			panic(err)
		}
		d := new(big.Int).SetBytes(okm)
		if d.Sign() > 0 && d.Cmp(n) < 0 {
			return okm
		}
	}
	panic("no scalar")
}

func main() {
	seed, err := hex.DecodeString(os.Args[1])
	if err != nil {
		panic(err)
	}
	prk, err := hkdf.Extract(sha256.New, seed, []byte("esp32-tang/v1"))
	if err != nil {
		panic(err)
	}
	for _, role := range []string{"signing", "exchange"} {
		d := derive(prk, role)
		k, err := ecdh.P256().NewPrivateKey(d)
		if err != nil {
			panic(err)
		}
		pub := k.PublicKey().Bytes() // 0x04 || X || Y
		x, y := pub[1:33], pub[33:65]
		canon := `{"crv":"P-256","kty":"EC","x":"` + b64(x) + `","y":"` + b64(y) + `"}`
		s256 := sha256.Sum256([]byte(canon))
		s1 := sha1.Sum([]byte(canon))
		fmt.Printf("%s d=%x\n  x=%s\n  s256=%s\n  s1=%s\n", role, d, b64(x), b64(s256[:]), b64(s1[:]))
	}
}
