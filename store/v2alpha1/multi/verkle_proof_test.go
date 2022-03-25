package multi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	abci "github.com/tendermint/tendermint/abci/types"

	"github.com/cosmos/cosmos-sdk/db/memdb"
	verklestore "github.com/cosmos/cosmos-sdk/store/verkle"
)

func TestVerifyVerkleStoreProof(t *testing.T) {
	// Create main tree for testing.
	txn := memdb.NewDB().ReadWriter()
	store := verklestore.NewStore(txn)
	store.Set([]byte("MYKEY"), []byte("MYVALUE"))
	root := store.GetRootCommitment()

	res, err := verkleProveKey(store, []byte("MYKEY"))
	require.NoError(t, err)

	// Verify good proof.
	err = VerifyVerkleProof(res, root, []byte("/"), map[string][]byte{verklestore.HashStr("MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.NoError(t, err)

	err = VerifyVerkleProof(res, root, []byte(""), map[string][]byte{verklestore.HashStr("MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.NoError(t, err)

	// Fail to verify bad proofs.
	err = VerifyVerkleProof(res, root, []byte("/"), map[string][]byte{verklestore.HashStr("MYKEY_NOT"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res, root, []byte("/"), map[string][]byte{verklestore.HashStr("MYKEY/MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res, root, []byte("/"), map[string][]byte{verklestore.HashStr("MYKEY"): verklestore.Hash([]byte("MYVALUE_NOT"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res, root, []byte("/"), map[string][]byte{verklestore.HashStr("MYKEY"): []byte(nil)})
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
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), map[string][]byte{verklestore.HashStr("MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.NoError(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), map[string][]byte{verklestore.HashStr("MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.NoError(t, err)

	// Fail to verify bad proofs.
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), map[string][]byte{verklestore.HashStr("MYKEY_NOT"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1/MYKEY"), map[string][]byte{verklestore.HashStr("MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1/"), map[string][]byte{verklestore.HashStr("MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("/"), map[string][]byte{verklestore.HashStr("MYKEY"): verklestore.Hash([]byte("MYVALUE"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), map[string][]byte{verklestore.HashStr("MYKEY"): verklestore.Hash([]byte("MYVALUE_NOT"))})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), map[string][]byte{verklestore.HashStr("MYKEY"): []byte(nil)})
	require.Error(t, err)

	require.Equal(t, res.Value, []byte("MYVALUE"))
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
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), map[string][]byte{verklestore.HashStr("MYABSENTKEY"): nil})
	require.NoError(t, err)

	// Fail to verify bad proofs.
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte(""), map[string][]byte{verklestore.HashStr("MYABSENTKEY"): nil})
	require.Error(t, err)

	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), map[string][]byte{verklestore.HashStr("MYABSENTKEY"): []byte("")})
	require.Error(t, err)
}

func TestVerifyMultiStoreQueryVerkleMultiProof(t *testing.T) {
	db := memdb.NewDB()
	store, err := NewStore(db, verkleSimpleStoreConfig(t))
	require.NoError(t, err)

	substore := store.GetKVStore(skey_1)
	substore.Set([]byte("MYKEY0"), []byte("MYVALUE0"))
	substore.Set([]byte("MYKEY1"), []byte("MYVALUE1"))
	substore.Set([]byte("MYKEY2"), []byte("MYVALUE2"))
	cid := store.Commit()

	data, err := json.Marshal([]string{"MYKEY0", "MYKEY1", "MYKEY2", "MYABSENTKEY"})
	require.NoError(t, err)

	res := store.Query(abci.RequestQuery{
		Path:  "/store1/key", // required path to get key/value+proof
		Data:  data,
		Prove: true,
	})

	// missing non-membership K
	kvMap := map[string][]byte{
		verklestore.HashStr("MYKEY0"): verklestore.Hash([]byte("MYVALUE0")),
		verklestore.HashStr("MYKEY1"): verklestore.Hash([]byte("MYVALUE1")),
		verklestore.HashStr("MYKEY2"): verklestore.Hash([]byte("MYVALUE2")),
	}
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), kvMap)
	require.Error(t, err)

	// missing membership KV
	kvMap = map[string][]byte{
		verklestore.HashStr("MYKEY0"):      verklestore.Hash([]byte("MYVALUE0")),
		verklestore.HashStr("MYKEY1"):      verklestore.Hash([]byte("MYVALUE1")),
		verklestore.HashStr("MYABSENTKEY"): nil,
	}
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), kvMap)
	require.Error(t, err)

	// wrong value for membership proof
	kvMap = map[string][]byte{
		verklestore.HashStr("MYKEY0"):      verklestore.Hash([]byte("MYVALUE0")),
		verklestore.HashStr("MYKEY1"):      verklestore.Hash([]byte("MYVALUE1")),
		verklestore.HashStr("MYKEY2"):      verklestore.Hash([]byte("MYVALUE1")),
		verklestore.HashStr("MYABSENTKEY"): nil,
	}
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), kvMap)
	require.Error(t, err)

	// missing value for membership proof
	kvMap = map[string][]byte{
		verklestore.HashStr("MYKEY0"):      verklestore.Hash([]byte("MYVALUE0")),
		verklestore.HashStr("MYKEY1"):      verklestore.Hash([]byte("MYVALUE1")),
		verklestore.HashStr("MYKEY2"):      nil,
		verklestore.HashStr("MYABSENTKEY"): nil,
	}
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), kvMap)
	require.Error(t, err)

	// wrong value for non-membership proof
	kvMap = map[string][]byte{
		verklestore.HashStr("MYKEY0"):      verklestore.Hash([]byte("MYVALUE0")),
		verklestore.HashStr("MYKEY1"):      verklestore.Hash([]byte("MYVALUE1")),
		verklestore.HashStr("MYKEY2"):      verklestore.Hash([]byte("MYVALUE2")),
		verklestore.HashStr("MYABSENTKEY"): verklestore.Hash([]byte("MYVALUE0")),
	}
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), kvMap)
	require.Error(t, err)

	// No error
	kvMap = map[string][]byte{
		verklestore.HashStr("MYKEY0"):      verklestore.Hash([]byte("MYVALUE0")),
		verklestore.HashStr("MYKEY1"):      verklestore.Hash([]byte("MYVALUE1")),
		verklestore.HashStr("MYKEY2"):      verklestore.Hash([]byte("MYVALUE2")),
		verklestore.HashStr("MYABSENTKEY"): nil,
	}
	err = VerifyVerkleProof(res.ProofOps, cid.Hash, []byte("store1"), kvMap)
	require.NoError(t, err)
	var values []string
	err = json.Unmarshal(res.GetValue(), &values)
	require.NoError(t, err)
	require.Equal(t, len(values), 4)
	require.Equal(t, values[0], "MYVALUE0")
	require.Equal(t, values[1], "MYVALUE1")
	require.Equal(t, values[2], "MYVALUE2")
	require.Equal(t, values[3], "")
}
