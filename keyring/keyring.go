package keyring

import (
	"github.com/ion-toolbox/keys-n-tokens/types"
)

var krInstance *KeyRing = nil

type KeyRing struct {
	keys map[string]*types.KeyPair
}

func SharedKeyRing() *KeyRing {
	if krInstance == nil {
		krInstance = &KeyRing{
			keys: make(map[string]*types.KeyPair),
		}
	}
	return krInstance
}

func (kr *KeyRing) AddKeyPair(name string, keypair *types.KeyPair) {
	kr.keys[name] = keypair
}

func (kr *KeyRing) GetKeyPair(name string) *types.KeyPair {
	return kr.keys[name]
}
