package verklestore

import (
	"bytes"
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
		keyPath := sha3.Sum256(iter.Key())
		var valuePath []byte
		if len(iter.Value()) == 0 {
			valuePath = zeroKey
		} else {
			v := sha3.Sum256(iter.Value())
			valuePath = v[:]
		}
		err = tree.Insert(keyPath[:], valuePath[:], nil)
		if err != nil {
			return nil
		}
	}
	err = iter.Close()
	if err != nil {
		panic(err)
	}

	return &Store{
		tree:      tree,
		values:    values,
		preimages: preimages,
	}
}

func (s *Store) GetRoot() verkle.VerkleNode {
	return s.tree
}

func (s *Store) GetProof(_ []byte) (*tmcrypto.ProofOps, error) {
	panic("not implemented")
}

func (s *Store) GetProofICS23(_ []byte) (*ics23.CommitmentProof, error) {
	panic("not implemented")
}

// BasicKVStore interface below:

// Get returns nil iff key doesn't exist. Panics on nil or empty key.
func (s *Store) Get(key []byte) []byte {
	if len(key) == 0 {
		panic(errKeyEmpty)
	}
	keyPath := sha3.Sum256(key)
	valPath, err := s.tree.Get(keyPath[:], nil)
	if err != nil {
		panic(err)
	}
	// key doesn't exist
	if valPath == nil {
		return []byte{}
	}
	val, err := s.values.Get(key)
	valPath2 := sha3.Sum256(val)
	if err != nil || !bytes.Equal(valPath2[:], valPath) {
		panic(err)
	}
	return val
}

// Has checks if a key exists. Panics on nil or empty key.
func (s *Store) Has(key []byte) bool {
	if len(key) == 0 {
		panic(errKeyEmpty)
	}
	keyPath := sha3.Sum256(key)
	valPath, err := s.tree.Get(keyPath[:], nil)
	if err != nil {
		panic(err)
	}
	if valPath == nil {
		return false
	}
	return !bytes.Equal(valPath, zeroKey)
}

// Set sets the key. Panics on nil key or value.
func (s *Store) Set(key []byte, value []byte) {
	if len(key) == 0 {
		panic(errKeyEmpty)
	}
	if value == nil {
		panic(errValueNil)
	}
	keyPath := sha3.Sum256(key)
	valuePath := sha3.Sum256(value)
	err := s.tree.Insert(keyPath[:], valuePath[:], nil)
	if err != nil {
		panic(err)
	}
	err = s.values.Set(key, value)
	if err != nil {
		return
	}
	err = s.preimages.Set(keyPath[:], key)
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
	err = s.values.Set(key, []byte{})
	if err != nil {
		return
	}
	// valuePath is not deleted in case there are duplicate values in the tree
	err = s.preimages.Delete(path[:])
	if err != nil {
		return
	}
}
