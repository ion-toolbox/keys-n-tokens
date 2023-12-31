package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ion-toolbox/keys-n-tokens/types"
	"net"
	"os"
	"strings"
	"time"
)

func NewPublicKeyFromString(s string) *types.KeyPair {
	return &types.KeyPair{
		Private: nil,
		Public:  base58.Decode(s),
	}
}

func NewPublicKeyFromEnv(env string) (*types.KeyPair, error) {
	val, ok := os.LookupEnv(env)
	if !ok {
		return nil, fmt.Errorf("can't find environment var %s", env)
	}
	return &types.KeyPair{
		Private: nil,
		Public:  base58.Decode(val),
	}, nil
}

func NewKeyPairFromFile(file string) *types.KeyPair {
	keyData, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	der, _ := pem.Decode(keyData)
	k, err := x509.ParsePKCS8PrivateKey(der.Bytes)
	if err != nil {
		panic(err)
	}

	return &types.KeyPair{
		Private: k.(ed25519.PrivateKey),
		Public:  k.(ed25519.PrivateKey).Public().(ed25519.PublicKey),
	}
}

func NewPublicKeyFromDns(ctx context.Context, fqdn string) (*types.KeyPair, error) {
	k := os.Getenv("CA")
	if k == "" {
		panic("No CA public key found")
	}

	resolver := os.Getenv("RESOLVER")
	keyData, err := (func() ([]string, error) {
		if resolver != "" {
			return (&net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Millisecond * time.Duration(10000),
					}
					return d.DialContext(ctx, "udp", resolver)
				},
			}).LookupTXT(ctx, fqdn)
		} else {
			return (&net.Resolver{}).LookupTXT(ctx, fqdn)
		}
	})()
	if err != nil {
		return nil, err
	}

	var key = ""
	for _, record := range keyData {
		parts := strings.Split(record, ":")
		if len(parts) != 2 {
			continue
		}
		if ed25519.Verify(base58.Decode(k), base58.Decode(parts[0]), base58.Decode(parts[1])) {
			key = parts[0]
		}
	}
	if key == "" {
		return nil, fmt.Errorf("DNS TXT signature check failed")
	}
	return &types.KeyPair{
		Private: nil,
		Public:  base58.Decode(key),
	}, nil
}
