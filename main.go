package main

import (
	"fmt"
	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"github.com/tronch0/two-party-ecdsa/party"
	"math/big"
)

func main() {

	fmt.Println("initiate two party computation for btc tx signing over ecdsa")

	msgToSign := []uint8(`
		Input:
		Previous tx: f5d8ee39a430901c91a5917b9f2dc19d6d1a0e9cea205b009ca73dd04470b9a6
		Index: 0
		scriptSig: 304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d10
		90db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501
		
		Output:
		Value: 5000000000
		scriptPubKey: OP_DUP OP_HASH160 404371705fa9bd789a2fcd52d2c580b65d35549d
		OP_EQUALVERIFY OP_CHECKSIG
	`)
	fmt.Printf("message to sign: %s\n", msgToSign)

	fmt.Println("generating party1 keys")
	p1PrivateKey := bigint.GetRandom()
	p1Key := ecdsa.NewPrivateKey(secp256k1.GetSecp256k1(), p1PrivateKey)
	p1 := party.NewWithKey(p1Key, msgToSign)

	fmt.Println("generating party2 keys")
	p2PrivateKey := bigint.GetRandom()
	p2Key := ecdsa.NewPrivateKey(secp256k1.GetSecp256k1(), p2PrivateKey)
	p2 := party.NewWithKey(p2Key, msgToSign)

	fmt.Println("party1: generating paillier keys and use paillier to encrypt its ecdsa private key")
	paiPub, privateKeyEnc, err := p1.InitializeSign()
	if err != nil {
		panic(err)
	}

	fmt.Println("party2: adding his private key to party1-encrypted-private key and use party1-public-paillier to encrypt his random")
	a, encB, R := p2.HandleInitializeSign(paiPub, privateKeyEnc)

	fmt.Println("party1: finalizing the computation with adding his random and decrypt the final value")

	sig, err := p1.FinalizedSign(a, encB, R)
	if err != nil {
		panic(err)
	}

	fmt.Printf("result signature -  r: %x, s: %x\n", sig.R.Bytes(), sig.S.Bytes())

	jointPrivKey := new(big.Int).Mul(p1PrivateKey, p2PrivateKey)
	jointPubKey := secp256k1.GetSecp256k1().GetG().ScalarMul(jointPrivKey)

	fmt.Printf("verifing signature agisnt the joint public key - public point: (%x, %x)\n", jointPubKey.GetX().GetNum().Bytes(), jointPubKey.GetY().GetNum().Bytes())

	z := bigint.HashBytesToBigInt(msgToSign)
	verfied := ecdsa.Verify(jointPubKey, z, sig, secp256k1.GetSecp256k1())

	fmt.Printf("verifing signature result - verified: %t\n", verfied)
}
