package multi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	ics23 "github.com/confio/ics23/go"
	verklestore "github.com/cosmos/cosmos-sdk/store/verkle"
	"github.com/gballet/go-verkle"
	"github.com/tendermint/tendermint/crypto/merkle"
	tmcrypto "github.com/tendermint/tendermint/proto/tendermint/crypto"
	"reflect"

	types "github.com/cosmos/cosmos-sdk/store/v2alpha1"
	"github.com/cosmos/cosmos-sdk/store/v2alpha1/smt"
)

// DefaultProofRuntime returns a ProofRuntime supporting SMT and simple merkle proofs.
func DefaultProofRuntime() (prt *merkle.ProofRuntime) {
	prt = merkle.NewProofRuntime()
	prt.RegisterOpDecoder(types.ProofOpSMTCommitment, types.CommitmentOpDecoder)
	prt.RegisterOpDecoder(types.ProofOpSimpleMerkleCommitment, types.CommitmentOpDecoder)
	return prt
}

// Prove commitment of key within an smt store and return ProofOps
func proveKey(s *smt.Store, key []byte) (*tmcrypto.ProofOps, error) {
	var ret tmcrypto.ProofOps
	keyProof, err := s.GetProofICS23(key)
	if err != nil {
		return nil, err
	}
	hkey := sha256.Sum256(key)
	ret.Ops = append(ret.Ops, types.NewSmtCommitmentOp(hkey[:], keyProof).ProofOp())
	return &ret, nil
}

// Prove commitment of key within an verkle store and return ProofOps
func verkleProveKey(s *verklestore.Store, jsonKeys []byte) (*tmcrypto.ProofOps, error) {
	var ret tmcrypto.ProofOps
	var keys []string
	err := json.Unmarshal(jsonKeys, &keys)
	if err != nil {
		keys = []string{string(jsonKeys)}
	}
	keyProof, err := s.GetProofICS23(keys)
	if err != nil {
		return nil, err
	}
	ret.Ops = append(ret.Ops, types.NewVerkleCommitmentOp(nil, keyProof).ProofOp())
	return &ret, nil
}

// verifyIcs23VerkleProof verifies Verkle proofs for both existence and nonexistence and batch proofs.
func verifyIcs23VerkleProofWithoutRoot(p *ics23.VerkleProof, kvs map[string][]byte) ([]byte, error) {
	// TODO: should not rebuild verkle tree from KVs
	tree := verkle.New()
	if len(p.Value) != len(p.Key) {
		return nil, fmt.Errorf("Temporary requirement: len of KV must match")
	}
	num := len(p.Value)
	for i := 0; i < num; i++ {
		err := tree.Insert(p.Key[i], p.Value[i], nil)
		if err != nil {
			return nil, err
		}
	}

	var keys [][]byte
	for key, val := range kvs {
		keys = append(keys, []byte(key))
		val2, err := tree.Get([]byte(key), nil)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(val, val2) {
			return nil, fmt.Errorf("Value mismatch for key:" + key)
		}
	}

	root := tree.ComputeCommitment().Bytes()
	cfg, err := verkle.GetConfig()
	if err != nil {
		return nil, err
	}
	proof, err := verkle.DeserializeProof(p.Proof)
	if err != nil {
		return nil, err
	}
	pe, _, _ := verkle.GetCommitmentsForMultiproof(tree, keys)
	if !verkle.VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, cfg) {
		return nil, fmt.Errorf("Failed to verify proof")
	}

	return root[:], nil
}

// VerifyVerkleProof verifies Verkle/Merkle proofs for both existence and nonexistence and batch proofs.
func VerifyVerkleProof(proofOps *tmcrypto.ProofOps, rootCommitment []byte, storeName []byte, keyVals map[string][]byte) error {
	var root []byte
	for _, p := range proofOps.GetOps() {
		proofStr := p.GetData()
		var ics23Proof ics23.CommitmentProof
		err := ics23Proof.Unmarshal(proofStr)
		if err != nil {
			return err
		}
		if ics23Proof.GetVerkle() != nil {
			root, err = verifyIcs23VerkleProofWithoutRoot(ics23Proof.GetVerkle(), keyVals)
			if err != nil {
				return err
			}
		} else {
			if root == nil {
				return fmt.Errorf("Invalid ProofOps")
			}
			if !bytes.Equal(storeName, p.GetKey()) {
				return fmt.Errorf("Wrong storeName")
			}
			prt := DefaultProofRuntime()
			operator, err := prt.Decode(p)
			if err != nil {
				return err
			}
			ret, err := operator.Run([][]byte{root})
			if err != nil {
				return err
			}
			root = ret[0]
		}
	}
	if !bytes.Equal(rootCommitment, root) {
		return fmt.Errorf("calculated root hash is invalid: expected %X but got %X", rootCommitment, root)
	}
	return nil
}

// GetProof returns ProofOps containing: a proof for the given key within this substore;
// and a proof of the substore's existence within the MultiStore.
func (s *viewSubstore) GetProof(key []byte) (*tmcrypto.ProofOps, error) {
	var ret *tmcrypto.ProofOps
	var err error

	if useVerkleTree(s.root.schema[s.name]) {
		ret, err = verkleProveKey(s.verkleStateCommitmentStore, key)
	} else {
		ret, err = proveKey(s.stateCommitmentStore, key)
	}
	if err != nil {
		return nil, err
	}

	// Prove commitment of substore within root store
	storeHashes, err := s.root.getMerkleRoots()
	if err != nil {
		return nil, err
	}
	storeProof, err := types.ProofOpFromMap(storeHashes, s.name)
	if err != nil {
		return nil, err
	}
	ret.Ops = append(ret.Ops, storeProof)
	return ret, nil
}
