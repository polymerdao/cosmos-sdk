package verkle

import (
	"bytes"
	"encoding/gob"

	"github.com/gballet/go-verkle"

	"github.com/cosmos/cosmos-sdk/store/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/proto/tendermint/crypto"
	"golang.org/x/crypto/sha3"
)

const (
	ProofType = "ipa" // verkle_Pedersen_IPA
)

type Proof struct {
	Key   []byte
	Proof *verkle.ProofElements
}

// ProofOp implements merkle.ProofOperator which is a layer for calculating
// intermediate Merkle roots when a series of Merkle trees are chained together.
type ProofOp struct {
	Root  verkle.VerkleNode
	Proof Proof
}

// NewProofOp returns a ProofOp for a Verkle Pedersen+IPA proof.
// https://dankradfeist.de/ethereum/2021/07/27/inner-product-arguments.html
func NewProofOp(root verkle.VerkleNode, key []byte, proof *verkle.ProofElements) *ProofOp {
	return &ProofOp{
		Root: root,
		Proof: Proof{
			Key:   key,
			Proof: proof,
		},
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
	keyPath := sha3.Sum256(p.GetKey())
	cfg, _ := verkle.GetConfig()
	pp := &p.Proof
	switch len(args) {
	case 0: // non-membership proof
		_, err := p.Root.Get(keyPath[:], nil)
		if err == nil {
			return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "proof did not verify absence of key: %s", pp.Key)
		}
		proof, _, _, _ = verkle.MakeVerkleMultiProof(p.Root, [][]byte{keyPath[:]}, map[string][]byte{string(zeroKey): zeroKey})
		if !verkle.VerifyVerkleProof(proof, pp.Proof.Cis, pp.Proof.Zis, pp.Proof.Yis, cfg) {
			return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "proof did not verify absence of key: %s", pp.Key)
		}
	case 1: // membership proof
		valArgsPath := sha3.Sum256(args[0])
		valPath, err := p.Root.Get(keyPath[:], nil)
		if bytes.Compare(valArgsPath[:], valPath) != 0 || err != nil {
			return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "proof did not verify existence of key %s with given value %x", pp.Key, args[0])
		}
		proof, _, _, _ = verkle.MakeVerkleMultiProof(p.Root, [][]byte{keyPath[:]}, map[string][]byte{string(keyPath[:]): valPath[:]})
		if !verkle.VerifyVerkleProof(proof, pp.Proof.Cis, pp.Proof.Zis, pp.Proof.Yis, cfg) {
			return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "proof did not verify existence of key %s with given value %x", pp.Key, args[0])
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
	return p.Proof.Key
}

func (p *ProofOp) ProofOp() crypto.ProofOp {
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	err := enc.Encode(p.Proof)
	if err != nil {
		return crypto.ProofOp{}
	}
	return crypto.ProofOp{
		Type: ProofType,
		Key:  p.GetKey(),
		Data: data.Bytes(),
	}
}

func ProofDecoder(pop crypto.ProofOp, root verkle.VerkleNode) (merkle.ProofOperator, error) {
	dec := gob.NewDecoder(bytes.NewBuffer(pop.Data))
	var proof Proof
	err := dec.Decode(&proof)
	if err != nil {
		return nil, err
	}
	return &ProofOp{
		Root:  root,
		Proof: proof,
	}, nil
}
