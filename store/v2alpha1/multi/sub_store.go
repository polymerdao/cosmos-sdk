package multi

import (
	"io"

	dbutil "github.com/cosmos/cosmos-sdk/internal/db"
	"github.com/cosmos/cosmos-sdk/store/cachekv"
	"github.com/cosmos/cosmos-sdk/store/listenkv"
	"github.com/cosmos/cosmos-sdk/store/tracekv"
	types "github.com/cosmos/cosmos-sdk/store/v2alpha1"
)

// Get implements KVStore.
func (s *substore) Get(key []byte) []byte {
	s.root.mtx.RLock()
	defer s.root.mtx.RUnlock()

	val, err := s.dataBucket.Get(key)
	if err != nil {
		panic(err)
	}
	return val
}

// Has implements KVStore.
func (s *substore) Has(key []byte) bool {
	s.root.mtx.RLock()
	defer s.root.mtx.RUnlock()

	has, err := s.dataBucket.Has(key)
	if err != nil {
		panic(err)
	}
	return has
}

// Set implements KVStore.
func (s *substore) Set(key, value []byte) {
	s.root.mtx.Lock()
	defer s.root.mtx.Unlock()

	err := s.dataBucket.Set(key, value)
	if err != nil {
		panic(err)
	}
	s.stateCommitmentStore.Set(key, value)
}

// Delete implements KVStore.
func (s *substore) Delete(key []byte) {
	s.root.mtx.Lock()
	defer s.root.mtx.Unlock()

	s.stateCommitmentStore.Delete(key)
	_ = s.dataBucket.Delete(key)
}

// Iterator implements KVStore.
func (s *substore) Iterator(start, end []byte) types.Iterator {
	iter, err := s.dataBucket.Iterator(start, end)
	if err != nil {
		panic(err)
	}
	return dbutil.ToStoreIterator(iter)
}

// ReverseIterator implements KVStore.
func (s *substore) ReverseIterator(start, end []byte) types.Iterator {
	iter, err := s.dataBucket.ReverseIterator(start, end)
	if err != nil {
		panic(err)
	}
	return dbutil.ToStoreIterator(iter)
}

// GetStoreType implements Store.
func (s *substore) GetStoreType() types.StoreType {
	return types.StoreTypePersistent
}

func (s *substore) CacheWrap() types.CacheWrap {
	return cachekv.NewStore(s)
}

func (s *substore) CacheWrapWithTrace(w io.Writer, tc types.TraceContext) types.CacheWrap {
	return cachekv.NewStore(tracekv.NewStore(s, w, tc))
}

func (s *substore) CacheWrapWithListeners(storeKey types.StoreKey, listeners []types.WriteListener) types.CacheWrap {
	return cachekv.NewStore(listenkv.NewStore(s, storeKey, listeners))
}
