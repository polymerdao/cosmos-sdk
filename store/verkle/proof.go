package verkle

import (
	"bytes"
	"encoding/gob"
	"github.com/gballet/go-verkle"

	"github.com/cosmos/cosmos-sdk/store/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/tendermint/tendermint/crypto/merkle"
	tmmerkle "github.com/tendermint/tendermint/proto/tendermint/crypto"
	"golang.org/x/crypto/sha3"
)

const (
	ProofType = "ipa" // verkle_Pedersen_IPA
)

// ProofOp implements merkle.ProofOperator which is a layer for calculating
// intermediate Merkle roots when a series of Merkle trees are chained together.
type ProofOp struct {
	Root   verkle.VerkleNode
	Key    []byte
	Proof  *verkle.ProofElements
	Config *verkle.Config
}

// NewProofOp returns a ProofOp for a Verkle Pedersen+IPA proof.
// https://dankradfeist.de/ethereum/2021/07/27/inner-product-arguments.html
func NewProofOp(root verkle.VerkleNode, key []byte, proof *verkle.ProofElements) *ProofOp {
	cfg, err := verkle.GetConfig()
	if err != nil {
		panic(err)
	}
	return &ProofOp{
		Root:   root,
		Key:    key,
		Proof:  proof,
		Config: cfg,
	}
}

// Run takes leaf values from a tree and returns the Merkle
// root for the corresponding tree. It takes and returns a list of bytes
// to allow multiple leaves to be part of a single proof,
// for instance in a range proof.
// TODO: support multiproofs; need to modify tendermint api.
func (p *ProofOp) Run(args [][]byte) ([][]byte, error) {
	var ret []byte
	var err error
	var proof *verkle.Proof
	keyPath := sha3.Sum256(p.Key)
	switch len(args) {
	case 0: // non-membership proof
		proof, _, _, _ = verkle.MakeVerkleMultiProof(p.Root, [][]byte{keyPath[:]}, map[string][]byte{string(zeroKey): zeroKey})
		if !verkle.VerifyVerkleProof(proof, p.Proof.Cis, p.Proof.Zis, p.Proof.Yis, p.Config) {
			return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "proof did not verify absence of key: %s", p.Key)
		}
	case 1: // membership proof
		valPath := sha3.Sum256(args[0])
		proof, _, _, _ = verkle.MakeVerkleMultiProof(p.Root, [][]byte{keyPath[:]}, map[string][]byte{string(keyPath[:]): valPath[:]})
		if !verkle.VerifyVerkleProof(proof, p.Proof.Cis, p.Proof.Zis, p.Proof.Yis, p.Config) {
			return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "proof did not verify existence of key %s with given value %x", p.Key, args[0])
		}
	default:
		return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "args must be length 0 or 1, got: %d", len(args))
	}
	ret, _, err = verkle.SerializeProof(proof)
	if err != nil {
		panic(err)
	}
	return [][]byte{ret}, nil
}

func (p *ProofOp) GetKey() []byte {
	return p.Key
}

func (p *ProofOp) ProofOp() tmmerkle.ProofOp {
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	err := enc.Encode(p)
	if err != nil {
		return tmmerkle.ProofOp{}
	}
	return tmmerkle.ProofOp{
		Type: ProofType,
		Key:  p.Key,
		Data: data.Bytes(),
	}
}

func ProofDecoder(pop tmmerkle.ProofOp) (merkle.ProofOperator, error) {
	dec := gob.NewDecoder(bytes.NewBuffer(pop.Data))
	var proof ProofOp
	err := dec.Decode(&proof)
	if err != nil {
		return nil, err
	}
	return &proof, nil
}
