package verklestore

import (
	"bytes"
	"encoding/gob"
	"github.com/gballet/go-verkle"

	"github.com/cosmos/cosmos-sdk/store/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/tendermint/tendermint/crypto/merkle"
	tmmerkle "github.com/tendermint/tendermint/proto/tendermint/crypto"
)

const (
	ProofType = "ipa" // verkle_Pedersen_IPA
)

// ProofOp defines an operation used for calculating Merkle root/verifying Verkle proof.
// TODO: we should NOT have KeyVals in this struct, however there is no way to verify proof without rebuild the tree.
//       Fix it when go-verkle is ready to rebuild the stateless tree from proof.
type ProofOp struct {
	KeyVals map[string][]byte
	Key     []byte
	Proof   *verkle.Proof
}

// NewProofOp returns a ProofOp for a Verkle Pedersen+IPA proof.
// https://dankradfeist.de/ethereum/2021/07/27/inner-product-arguments.html
func NewProofOp(keyvals map[string][]byte, key []byte, proof *verkle.Proof) *ProofOp {
	return &ProofOp{
		KeyVals: keyvals,
		Key:     key,
		Proof:   proof,
	}
}

// Run TODO: support multiproofs; may need to modify tendermint core.
func (p *ProofOp) Run(args [][]byte) ([][]byte, error) {
	cfg, err := verkle.GetConfig()
	root := verkle.New()
	for key, val := range p.KeyVals {
		err := root.Insert([]byte(key), val, nil)
		if err != nil {
			return nil, err
		}
	}

	comm := root.ComputeCommitment().Bytes()
	pe, _, _ := verkle.GetCommitmentsForMultiproof(root, [][]byte{p.Key})
	if err != nil {
		return nil, err
	}
	switch len(args) {
	case 0: // non-membership proof
		val, err := root.Get(p.Key, nil)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(val, nil) || !verkle.VerifyVerkleProof(p.Proof, pe.Cis, pe.Zis, pe.Yis, cfg) {
			return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "proof did not verify absence of key: %s", p.Key)
		}
	case 1: // membership proof
		val, err := root.Get(p.Key, nil)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(val, args[0]) || !verkle.VerifyVerkleProof(p.Proof, pe.Cis, pe.Zis, pe.Yis, cfg) {
			return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "proof did not verify existence of key %s with given value %x", p.Key, args[0])
		}
	default:
		return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "args must be length 0 or 1, got: %d", len(args))
	}
	return [][]byte{comm[:]}, nil
}

func (p *ProofOp) GetKey() []byte {
	return p.Key
}

func (p *ProofOp) ProofOp() tmmerkle.ProofOp {
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	enc.Encode(p)
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
