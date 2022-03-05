package verkle

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/db/memdb"
	"github.com/stretchr/testify/assert"
)

func TestGetSetHasDelete(t *testing.T) {
	db := memdb.NewDB()
	s := NewStore(db.ReadWriter())

	s.Delete([]byte("foo"))
	assert.Equal(t, false, s.Has([]byte("foo")))
	s.Set([]byte("foo"), []byte("bar"))
	assert.Equal(t, []byte("bar"), s.Get([]byte("foo")))
	assert.Equal(t, true, s.Has([]byte("foo")))
	s.Delete([]byte("foo"))
	assert.Equal(t, false, s.Has([]byte("foo")))

	assert.Panics(t, func() { s.Get(nil) }, "Get(nil key) should panic")
	assert.Panics(t, func() { s.Get([]byte{}) }, "Get(empty key) should panic")
	assert.Panics(t, func() { s.Has(nil) }, "Has(nil key) should panic")
	assert.Panics(t, func() { s.Has([]byte{}) }, "Has(empty key) should panic")
	assert.Panics(t, func() { s.Set(nil, []byte("value")) }, "Set(nil key) should panic")
	assert.Panics(t, func() { s.Set([]byte{}, []byte("value")) }, "Set(empty key) should panic")
	assert.Panics(t, func() { s.Set([]byte("key"), nil) }, "Set(nil value) should panic")
}

func TestLoadStore(t *testing.T) {
	db := memdb.NewDB()
	txn := db.ReadWriter()
	s := NewStore(txn)

	s.Set([]byte{0}, []byte{0})
	s.Set([]byte{1}, []byte{1})
	s.Delete([]byte{1})
	ss, err := s.tree.Serialize()
	assert.Equal(t, err, nil)

	s2 := LoadStore(txn)
	ss2, err2 := s2.tree.Serialize()
	assert.Equal(t, ss, ss2)
	assert.Equal(t, []byte{0}, s2.Get([]byte{0}))
	assert.False(t, s2.Has([]byte{1}))
	s2.Set([]byte{2}, []byte{2})

	ss2, err2 = s2.tree.Serialize()
	assert.Equal(t, err2, nil)
	assert.NotEqual(t, ss, ss2)
}
