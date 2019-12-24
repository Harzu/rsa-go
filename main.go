package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

const (
	defaultBits    = 2048
	publicExponent = 65537
)

// RSAPrivateKeys - struct for private rsa keys
type RSAPrivateKeys struct {
	N *big.Int
	D *big.Int
	E *big.Int
}

func generateKeys() RSAPrivateKeys {
	e := big.NewInt(publicExponent)

	p, q := generatePrime(defaultBits), generatePrime(defaultBits)
	n := new(big.Int)
	n.Mul(p, q)

	eilerFunc := generateEilerFunc(p, q)

	d := new(big.Int)
	d.ModInverse(e, eilerFunc)

	return RSAPrivateKeys{
		D: d,
		N: n,
		E: e,
	}
}

func generatePrime(bits int) *big.Int {
	prime, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	return prime
}

func generateEilerFunc(p, q *big.Int) *big.Int {
	x := new(big.Int)
	y := new(big.Int)

	x.Sub(p, big.NewInt(1))
	y.Sub(q, big.NewInt(1))

	eiler := new(big.Int)
	eiler.Mul(x, y)

	return eiler
}

func (pk RSAPrivateKeys) privateDecrypt(cipher *big.Int) []byte {
	message := new(big.Int)
	message.Exp(cipher, pk.D, pk.N)

	return message.Bytes()
}

// RSAPublicKeys - struct for rsa public keys
type RSAPublicKeys struct {
	N *big.Int
	E *big.Int
}

func importPublicKeys(n, e *big.Int) RSAPublicKeys {
	return RSAPublicKeys{
		N: n,
		E: e,
	}
}

func (pk RSAPublicKeys) publicEncrypt(msg []byte) *big.Int {
	msgToBI := new(big.Int)
	msgToBI.SetBytes(msg)

	cipher := new(big.Int)
	cipher.Exp(msgToBI, pk.E, pk.N)

	return cipher
}

func elapsed(what string) func() {
	start := time.Now()
	return func() {
		fmt.Printf("%s took %v\n", what, time.Since(start))
	}
}

func main() {
	defer elapsed("time")()

	private := generateKeys()
	public := importPublicKeys(private.N, private.E)

	message := []byte("Hello, world")
	cipher := public.publicEncrypt(message)

	decrypted := private.privateDecrypt(cipher)

	fmt.Println(string(decrypted))
}
