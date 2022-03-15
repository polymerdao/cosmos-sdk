// Here we implement proof generation according to the ICS-23 specification:
// https://github.com/cosmos/ibc/tree/master/spec/core/ics-023-vector-commitments

package verklestore

import (
	ics23 "github.com/confio/ics23/go"
	"github.com/gballet/go-verkle"
	"golang.org/x/crypto/sha3"
)

func createIcs23Proof(store *Store, key []byte) (*ics23.CommitmentProof, error) {
	ret := &ics23.CommitmentProof{}
	keyPath := sha3.Sum256(key)
	// TODO: should not use all KVs
	kvs := store.GetTreeKV()
	proof, _, _, _ := verkle.MakeVerkleMultiProof(store.tree, [][]byte{keyPath[:]}, kvs)
	proofStr, _, err := verkle.SerializeProof(proof)
	if err != nil {
		return nil, err
	}

	var keys, vals [][]byte
	for k, v := range kvs {
		keys = append(keys, []byte(k))
		vals = append(vals, v)
	}

	ret.Proof = &ics23.CommitmentProof_Verkle{Verkle: &ics23.VerkleProof{
		Key:   keys,
		Value: vals,
		Proof: proofStr,
	}}
	return ret, nil
}
