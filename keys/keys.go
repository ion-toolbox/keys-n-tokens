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

func NewKeyPairFromDns(ctx context.Context, fqdn string) (*types.KeyPair, error) {
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
	parts := strings.Split(keyData[0], ":")
	k := os.Getenv("CA")
	if k == "" {
		panic("No CA public key found")
	}
	if !ed25519.Verify(base58.Decode(k), base58.Decode(parts[0]), base58.Decode(parts[1])) {
		return nil, fmt.Errorf("DNS TXT signature check failed")
	}
	return &types.KeyPair{
		Private: nil,
		Public:  base58.Decode(parts[0]),
	}, nil
}
