package party

import (
	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"math/big"
	"testing"
)

func TestNew(t *testing.T) {
	btcTx := []uint8("transfer 3 btc to address 1bc3e4353nej")

	p := New(btcTx)

	if p.d == nil {
		t.FailNow()
	}
	if p.k == nil {
		t.FailNow()
	}

	if p.selfPaillier == nil {
		t.FailNow()
	}
}

func TestFullFlow(t *testing.T) {
	btcTx := []uint8("transfer 3 btc to address 1bc3e4353nej")
	p1 := New(btcTx)
	p2 := New(btcTx)

	paillierPub, encD := p1.InitializeSign()

	a, encB, R := p2.HandleInitializeSign(paillierPub, encD)

	sig := p1.FinalizedSign(a, encB, R)

	jointPK := p1.GetKey().PublicKey.ScalarMul(p2.GetKey().Key)

	res := ecdsa.Verify(jointPK, bigint.HashBytesToBigInt(btcTx), sig, secp256k1.GetSecp256k1())

	if res == false {
		t.FailNow()
	}
}

func TestBadKeys(t *testing.T) {
	btcTx := []uint8("transfer 3 btc to address 1bc3e4353nej")
	p1 := New(btcTx)
	p2 := New(btcTx)

	paillierPub, encD := p1.InitializeSign()

	a, encB, R := p2.HandleInitializeSign(paillierPub, encD)

	sig := p1.FinalizedSign(a, encB, R)

	p1Key := p1.GetKey()
	p2Key := p2.GetKey()

	diffPrivateKey := new(big.Int).Add(p2Key.Key, new(big.Int).SetInt64(1))
	jointPK := p1Key.PublicKey.ScalarMul(diffPrivateKey)

	res := ecdsa.Verify(jointPK, bigint.HashBytesToBigInt(btcTx), sig, secp256k1.GetSecp256k1())

	if res == true {
		t.FailNow()
	}
}

func TestBadRandom(t *testing.T) {
	btcTx := []uint8("transfer 3 btc to address 1bc3e4353nej")
	p1 := New(btcTx)
	p2 := New(btcTx)

	paillierPub, encD := p1.InitializeSign()

	a, encB, R := p2.HandleInitializeSign(paillierPub, encD)

	diffR := R.ScalarMul(new(big.Int).SetInt64(2))
	sig := p1.FinalizedSign(a, encB, diffR)

	p1Key := p1.GetKey()
	p2Key := p2.GetKey()

	jointPK := p1Key.PublicKey.ScalarMul(p2Key.Key)

	res := ecdsa.Verify(jointPK, bigint.HashBytesToBigInt(btcTx), sig, secp256k1.GetSecp256k1())

	if res == true {
		t.FailNow()
	}
}
