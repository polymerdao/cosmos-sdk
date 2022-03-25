package verklestore

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cosmos/cosmos-sdk/db/memdb"
)

func TestProofICS23(t *testing.T) {
	txn := memdb.NewDB().ReadWriter()
	s := NewStore(txn)
	// pick keys whose hashes begin with different bits
	key00 := []byte("foo")
	key01 := []byte("bill")
	key10 := []byte("baz")
	key11 := []byte("bar")
	path00 := Hash(key00)
	path01 := Hash(key01)
	path10 := Hash(key10)
	path11 := Hash(key11)
	val1 := []byte("0")
	val2 := []byte("1")
	val1Path := Hash(val1)
	val2Path := Hash(val2)

	s.Set(key01, val1)
	rootCommitment := s.GetRootCommitment()

	// Membership
	proof, err := s.GetProofICS23([]string{string(key01)})
	assert.NoError(t, err)
	verkleProof01 := proof.GetVerkle()
	assert.NotNil(t, verkleProof01)
	assert.NoError(t, verkleProof01.Verify(rootCommitment, map[string][]byte{string(path01): val1Path}))

	// Non-membership
	proof, err = s.GetProofICS23([]string{string(key00)}) // When leaf is leftmost node
	assert.NoError(t, err)
	verkleProof := proof.GetVerkle()
	assert.NotNil(t, verkleProof)
	assert.NoError(t, verkleProof.Verify(rootCommitment, map[string][]byte{string(path00): nil}))

	s.Set(key11, val2)
	rootCommitment = s.GetRootCommitment()

	// Make sure proofs work with a loaded store
	s = LoadStore(txn)
	proof, err = s.GetProofICS23([]string{string(key10)})
	assert.NoError(t, err)
	verkleProof = proof.GetVerkle()
	assert.NoError(t, verkleProof.Verify(rootCommitment, map[string][]byte{string(path10): nil}))

	// Invalid proofs should fail to verify
	expiredProof := verkleProof01
	assert.Error(t, expiredProof.Verify(rootCommitment, map[string][]byte{string(path01): val1Path}))

	// Invalid key
	assert.Error(t, verkleProof.Verify(rootCommitment, map[string][]byte{string(path00): nil}))
	assert.Error(t, expiredProof.Verify(rootCommitment, map[string][]byte{string(path00): val2Path}))

	// Invalid Value
	assert.Error(t, verkleProof.Verify(rootCommitment, map[string][]byte{string(path10): val1}))
	assert.Error(t, expiredProof.Verify(rootCommitment, map[string][]byte{string(path11): val1Path}))
}
