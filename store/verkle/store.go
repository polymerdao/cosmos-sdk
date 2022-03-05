package verkle

import (
	"encoding/hex"
	"errors"
	"github.com/gballet/go-verkle"
	"golang.org/x/crypto/sha3"

	ics23 "github.com/confio/ics23/go"
	dbm "github.com/cosmos/cosmos-sdk/db"
	"github.com/cosmos/cosmos-sdk/db/prefix"
	tmcrypto "github.com/tendermint/tendermint/proto/tendermint/crypto"
)

var (
	// Verkle Trie does not require store Nodes
	// nodesPrefix     = []byte{0}
	valuesPrefix    = []byte{1}
	preimagesPrefix = []byte{2}

	zeroKey, _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")

	errKeyEmpty = errors.New("key is empty or nil")
	errValueNil = errors.New("value is nil")
)

// Store Implements types.KVStore and CommitKVStore.
type Store struct {
	tree   verkle.VerkleNode
	values dbm.DBReadWriter
	// Map hashed keys back to preimage
	preimages dbm.DBReadWriter
}

func NewStore(db dbm.DBReadWriter) *Store {
	values := prefix.NewPrefixReadWriter(db, valuesPrefix)
	preimages := prefix.NewPrefixReadWriter(db, preimagesPrefix)
	return &Store{
		tree:      verkle.New(),
		values:    values,
		preimages: preimages,
	}
}

// LoadStore TODO: this function can be optimized.
func LoadStore(db dbm.DBReadWriter) *Store {
	values := prefix.NewPrefixReadWriter(db, valuesPrefix)
	preimages := prefix.NewPrefixReadWriter(db, preimagesPrefix)
	tree := verkle.New()
	iter, err := values.Iterator(nil, nil)
	if err != nil {
		return nil
	}
	for iter.Next() {
		err = tree.Insert(iter.Key(), iter.Value(), nil)
		if err != nil {
			return nil
		}
	}
	iter.Close()

	return &Store{
		tree:      tree,
		values:    values,
		preimages: preimages,
	}
}

func (s *Store) GetProof(key []byte) (*tmcrypto.ProofOps, error) {
	panic("not implemented")
}

func (s *Store) GetProofICS23(key []byte) (*ics23.CommitmentProof, error) {
	panic("not implemented")
}

// BasicKVStore interface below:

// Get returns nil iff key doesn't exist. Panics on nil or empty key.
func (s *Store) Get(key []byte) []byte {
	if len(key) == 0 {
		panic(errKeyEmpty)
	}
	path := sha3.Sum256(key)
	val, err := s.tree.Get(path[:], nil)
	if err != nil {
		panic(err)
	}
	return val
}

// Has checks if a key exists. Panics on nil or empty key.
func (s *Store) Has(key []byte) bool {
	if len(key) == 0 {
		panic(errKeyEmpty)
	}
	path := sha3.Sum256(key)
	has, err := s.preimages.Has(path[:])
	if err != nil {
		return false
	}
	return has
}

// Set sets the key. Panics on nil key or value.
func (s *Store) Set(key []byte, value []byte) {
	if len(key) == 0 {
		panic(errKeyEmpty)
	}
	if value == nil {
		panic(errValueNil)
	}
	path := sha3.Sum256(key)
	err := s.tree.Insert(path[:], value, nil)
	if err != nil {
		panic(err)
	}
	err = s.values.Set(path[:], value)
	if err != nil {
		return
	}
	err = s.preimages.Set(path[:], key)
	if err != nil {
		return
	}
}

// Delete deletes the key. Panics on nil key.
// In verkle tree, the value is set to zero instead of deleting.
func (s *Store) Delete(key []byte) {
	if len(key) == 0 {
		panic(errKeyEmpty)
	}
	path := sha3.Sum256(key)
	err := s.tree.Delete(path[:])
	if err != nil {
		// trying to delete non-existent leaf.
		return
	}
	err = s.values.Set(path[:], zeroKey)
	if err != nil {
		return
	}
	err = s.preimages.Delete(path[:])
	if err != nil {
		return
	}
}
