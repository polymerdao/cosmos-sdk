package verklestore

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/db/memdb"
	"github.com/gballet/go-verkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProofOpInterface(t *testing.T) {
	db := memdb.NewDB()
	tree := NewStore(db.ReadWriter())
	keyPreimage := []byte("foo")
	valPreimage := []byte("bar")
	tree.Set(keyPreimage, valPreimage)

	key := Hash(keyPreimage)
	val := Hash(valPreimage)
	keyval := map[string][]byte{string(key): val}

	root := tree.GetRoot()
	comm := root.ComputeCommitment().Bytes()
	proof, _, _, _ := verkle.MakeVerkleMultiProof(root, [][]byte{key}, keyval)

	storeProofOp := NewProofOp(tree.GetTreeKV(), key, proof)
	require.NotNil(t, storeProofOp)
	// inclusion proof
	r, err := storeProofOp.Run([][]byte{val})
	assert.NoError(t, err)
	assert.Equal(t, comm[:], r[0])

	// inclusion proof - wrong value - should fail
	r, err = storeProofOp.Run([][]byte{key})
	assert.Error(t, err)
	assert.Empty(t, r)

	// exclusion proof - should fail
	r, err = storeProofOp.Run([][]byte{})
	assert.Error(t, err)
	assert.Empty(t, r)

	// exclusion proof - should pass
	key2 := Hash([]byte{1, 2, 3})
	proof2, _, _, _ := verkle.MakeVerkleMultiProof(root, [][]byte{key2}, map[string][]byte{string(key): val})
	storeProofOp2 := NewProofOp(keyval, key2, proof2)
	r, err = storeProofOp2.Run([][]byte{})
	assert.NoError(t, err)
	assert.Equal(t, comm[:], r[0])

	// invalid request - should fail
	r, err = storeProofOp.Run([][]byte{key, key})
	assert.Error(t, err)
	assert.Empty(t, r)

	// encode
	tmProofOp := storeProofOp.ProofOp()
	assert.NotNil(t, tmProofOp)
	assert.Equal(t, ProofType, tmProofOp.Type)
	assert.Equal(t, key, tmProofOp.Key, key)
	assert.NotEmpty(t, tmProofOp.Data)

	//decode
	decoded, err := ProofDecoder(tmProofOp)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)
	assert.Equal(t, key, decoded.GetKey())

	// run proof after decoding
	r, err = decoded.Run([][]byte{val})
	assert.NoError(t, err)
	assert.NotEmpty(t, r)
	assert.Equal(t, comm[:], r[0])
}
