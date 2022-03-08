package verkle

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/db/memdb"
	"github.com/gballet/go-verkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestProofOpInterface(t *testing.T) {
	db := memdb.NewDB()
	tree := NewStore(db.ReadWriter())
	key := []byte("foo")
	val := []byte("bar")
	tree.Set(key, val)
	root := tree.GetRoot()

	keyPath := sha3.Sum256(key)
	valPath := sha3.Sum256(val)

	root.ComputeCommitment()
	pe, _, _ := root.GetProofItems([][]byte{keyPath[:]})
	proof, _, _, _ := verkle.MakeVerkleMultiProof(root, [][]byte{keyPath[:]}, map[string][]byte{string(keyPath[:]): valPath[:]})
	config, err := verkle.GetConfig()
	assert.NoError(t, err)
	require.True(t, verkle.VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, config))

	storeProofOp := NewProofOp(root, key, pe)
	require.NotNil(t, storeProofOp)

	// inclusion proof
	r, err := storeProofOp.Run([][]byte{val})
	assert.NoError(t, err)
	assert.NotEmpty(t, r)
	pf, err := verkle.DeserializeProof(r[0])
	require.NoError(t, err)
	require.True(t, verkle.VerifyVerkleProof(pf, pe.Cis, pe.Zis, pe.Yis, config))

	// inclusion proof - wrong value - should fail
	r, err = storeProofOp.Run([][]byte{key})
	assert.Error(t, err)
	assert.Empty(t, r)

	// exclusion proof - should fail
	r, err = storeProofOp.Run([][]byte{})
	assert.Error(t, err)
	assert.Empty(t, r)

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

	// decode
	decodedWithoutRoot, err := ProofDecoder(tmProofOp, nil)
	assert.NoError(t, err)
	assert.NotNil(t, decodedWithoutRoot)
	assert.Equal(t, key, decodedWithoutRoot.GetKey())

	// run proof after decoding
	decodedWithRoot, err := ProofDecoder(tmProofOp, root)
	assert.NoError(t, err)
	r, err = decodedWithRoot.Run([][]byte{val})
	assert.NoError(t, err)
	assert.NotEmpty(t, r)
}
