package party

import (
	"crypto/rand"
	"github.com/tronch0/crypt0/paillier"

	"github.com/tronch0/crypt0/bigint"

	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"math/big"
)

type Party struct {
	d            *ecdsa.PrivateKey
	k            *big.Int
	selfPaillier *paillier.PrivateKey
	msg          []uint8
}

func New(msg []uint8) *Party {
	paillierKeyPair, _ := paillier.GenerateKey(rand.Reader)

	return &Party{
		k:            bigint.GetRandom(),
		d:            ecdsa.NewPrivateKey(secp256k1.GetSecp256k1(), bigint.GetRandom()),
		selfPaillier: paillierKeyPair,
		msg:          msg,
	}
}

func NewWithKey(key *ecdsa.PrivateKey, msg []uint8) *Party {
	paillierKeyPair, _ := paillier.GenerateKey(rand.Reader)

	return &Party{
		k:            bigint.GetRandom(),
		d:            key,
		selfPaillier: paillierKeyPair,
		msg:          msg,
	}
}

func (p *Party) GetKey() *ecdsa.PrivateKey {
	return p.d
}

func (p *Party) InitializeSign() (paiPubKey *paillier.PublicKey, encD []uint8, err error) {
	paiPubKey = &p.selfPaillier.PublicKey
	encD, err = paillier.Encrypt(&p.selfPaillier.PublicKey, p.d.Key.Bytes())
	if err != nil {
		return nil, nil, err
	}

	return
}

func (p *Party) HandleInitializeSign(paiPubKey *paillier.PublicKey, encD []uint8) (a *big.Int, encB []uint8, R *point.Point) {
	kInverse := new(big.Int).ModInverse(p.k, p.d.Curve.GetN())
	dMulKInv := new(big.Int).Mul(kInverse, p.d.Key)
	encB = paillier.Mul(paiPubKey, encD, dMulKInv.Bytes())

	e := bigint.HashBytesToBigInt(p.msg)
	a = new(big.Int).Mul(kInverse, e)

	R = p.d.Curve.GetG().ScalarMul(p.k)

	return
}

func (p *Party) FinalizedSign(a *big.Int, encB []uint8, R *point.Point) (*ecdsa.Signature, error) {
	jointR := R.ScalarMul(p.k)

	kInverse := new(big.Int).ModInverse(p.k, p.d.Curve.GetN())
	a = new(big.Int).Mul(a, kInverse)

	bBytes, err := paillier.Decrypt(p.selfPaillier, encB)
	if err != nil {
		return nil, err
	}

	b := new(big.Int).SetBytes(bBytes)
	b = new(big.Int).Mul(b, kInverse)
	b = new(big.Int).Mul(b, jointR.GetX().GetNum())

	r := new(big.Int).Mod(jointR.GetX().GetNum(), p.d.Curve.GetN())
	s := new(big.Int).Mod(new(big.Int).Add(a, b), p.d.Curve.GetN())
	return &ecdsa.Signature{
		R: r,
		S: s,
	}, nil
}
