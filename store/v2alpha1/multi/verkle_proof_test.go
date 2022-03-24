package multi

import (
	"testing"

	"github.com/stretchr/testify/require"
	abci "github.com/tendermint/tendermint/abci/types"

	"github.com/cosmos/cosmos-sdk/db/memdb"
	verklestore "github.com/cosmos/cosmos-sdk/store/verkle"
)

// We hash keys produce verkle paths, so reflect that here
func verkleKeyPath(prefix, key string) string {
	hashed := verklestore.Hash([]byte(key))
	return prefix + string(hashed)
}

func TestVerifyVerkleStoreProof(t *testing.T) {
	// Create main tree for testing.
	txn := memdb.NewDB().ReadWriter()
	store := verklestore.NewStore(txn)
	store.Set([]byte("MYKEY"), []byte("MYVALUE"))
	root := store.GetRootCommitment()

	res, err := verkleProveKey(store, []byte("MYKEY"))
	require.NoError(t, err)

	// Verify good proof.
	err = VerifyVerkleProof(res, root, map[string][]byte{verkleKeyPath("/", "MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.NoError(t, err)

	// Fail to verify bad proofs.
	err = VerifyVerkleProof(res, root, map[string][]byte{verkleKeyPath("/", "MYKEY_NOT"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res, root, map[string][]byte{verkleKeyPath("/", "MYKEY/MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res, root, map[string][]byte{verkleKeyPath("", "MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res, root, map[string][]byte{verkleKeyPath("/", "MYKEY"): verklestore.Hash([]byte("MYVALUE_NOT"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res, root, map[string][]byte{verkleKeyPath("/", "MYKEY"): []byte(nil)})
	require.Error(t, err)
}

func TestVerifyMultiStoreQueryVerkleProof(t *testing.T) {
	db := memdb.NewDB()
	store, err := NewStore(db, verkleSimpleStoreConfig(t))
	require.NoError(t, err)

	substore := store.GetKVStore(skey_1)
	substore.Set([]byte("MYKEY"), []byte("MYVALUE"))
	cid := store.Commit()

	res := store.Query(abci.RequestQuery{
		Path:  "/store1/key", // required path to get key/value+proof
		Data:  []byte("MYKEY"),
		Prove: true,
	})
	require.NotNil(t, res.ProofOps)

	// Verify good proofs.
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/store1/", "MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.NoError(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/store1/", "MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.NoError(t, err)

	// Fail to verify bad proofs.
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/store1/", "MYKEY_NOT"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/store1/MYKEY/", "MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("store1/", "MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/", "MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/store1/", "MYKEY"): verklestore.Hash([]byte("MYVALUE_NOT"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/store1/", "MYKEY"): []byte(nil)})
	require.Error(t, err)
}

func TestVerifyMultiStoreQueryVerkleProofAbsence(t *testing.T) {
	db := memdb.NewDB()
	store, err := NewStore(db, verkleSimpleStoreConfig(t))
	require.NoError(t, err)

	substore := store.GetKVStore(skey_1)
	substore.Set([]byte("MYKEY"), []byte("MYVALUE"))
	cid := store.Commit()

	res := store.Query(abci.RequestQuery{
		Path:  "/store1/key", // required path to get key/value+proof
		Data:  []byte("MYABSENTKEY"),
		Prove: true,
	})
	require.NotNil(t, res.ProofOps)

	// Verify good proof.
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/store1/", "MYABSENTKEY"): nil})
	require.NoError(t, err)

	// Fail to verify bad proofs.
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/", "MYABSENTKEY"): nil})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, map[string][]byte{verkleKeyPath("/store1/", "MYABSENTKEY"): []byte("")})
	require.Error(t, err)
}
