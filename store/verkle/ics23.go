// Here we implement proof generation according to the ICS-23 specification:
// https://github.com/cosmos/ibc/tree/master/spec/core/ics-023-vector-commitments

package verklestore

import (
	"errors"
	ics23 "github.com/confio/ics23/go"
	"github.com/gballet/go-verkle"
)

func createIcs23Proof(store *Store, keys []string) (*ics23.CommitmentProof, error) {
	ret := &ics23.CommitmentProof{}
	var keyPaths [][]byte
	for _, k := range keys {
		keyPaths = append(keyPaths, Hash([]byte(k)))
	}
	// TODO: should not use all KVs
	kvs := store.GetTreeKV()
	proof, _, _, _ := verkle.MakeVerkleMultiProof(store.tree, keyPaths, kvs)
	if len(proof.Keys) != len(keyPaths) {
		return nil, errors.New("wrong key in verkle proof")
	}
	proofStr, _, err := verkle.SerializeProof(proof)
	if err != nil {
		return nil, err
	}

	var allKeys, allVals [][]byte
	for k, v := range kvs {
		// TODO: This is just for trials till go-verkle supports proofKV
		allKeys = append(allKeys, []byte(k))
		allVals = append(allVals, v)
	}

	ret.Proof = &ics23.CommitmentProof_Verkle{Verkle: &ics23.VerkleProof{
		Key:   allKeys,
		Value: allVals,
		Proof: proofStr,
	}}
	return ret, nil
}
