package verklestore

import (
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/cosmos/cosmos-sdk/db/memdb"
	"github.com/stretchr/testify/assert"
)

func TestGetSetHasDelete(t *testing.T) {
	db := memdb.NewDB()
	s := NewStore(db.ReadWriter())

	comm := s.GetRootCommitment()
	assert.Equal(t, zeroKey, comm)
	s.Delete([]byte("foo"))
	assert.Equal(t, false, s.Has([]byte("foo")))
	s.Set([]byte("foo"), []byte("bar"))
	comm = s.GetRootCommitment()
	assert.Equal(t, []byte("bar"), s.Get([]byte("foo")))
	assert.Equal(t, true, s.Has([]byte("foo")))
	s.Delete([]byte("foo"))
	// The value is set to zero instead of deleting, so the root commitment is not equal to the previous one
	comm2 := s.GetRootCommitment()
	assert.NotEqual(t, comm, comm2)
	assert.Equal(t, false, s.Has([]byte("foo")))
	assert.Equal(t, []byte{}, s.Get([]byte("bar")))

	assert.Panics(t, func() { s.Get(nil) }, "Get(nil key) should panic")
	assert.Panics(t, func() { s.Get([]byte{}) }, "Get(empty key) should panic")
	assert.Panics(t, func() { s.Has(nil) }, "Has(nil key) should panic")
	assert.Panics(t, func() { s.Has([]byte{}) }, "Has(empty key) should panic")
	assert.Panics(t, func() { s.Set(nil, []byte("value")) }, "Set(nil key) should panic")
	assert.Panics(t, func() { s.Set([]byte{}, []byte("value")) }, "Set(empty key) should panic")
	assert.Panics(t, func() { s.Set([]byte("key"), nil) }, "Set(nil value) should panic")

	s.Set([]byte("foo1foo2foo3foo4foo5foo6foo7foo8foo9"), []byte("bar1bar2bar3bar4bar5bar6bar7bar8bar9"))
	assert.Equal(t, []byte("bar1bar2bar3bar4bar5bar6bar7bar8bar9"), s.Get([]byte("foo1foo2foo3foo4foo5foo6foo7foo8foo9")))
	assert.Equal(t, true, s.Has([]byte("foo1foo2foo3foo4foo5foo6foo7foo8foo9")))
}

func TestLoadStore(t *testing.T) {
	db := memdb.NewDB()
	txn := db.ReadWriter()
	s := NewStore(txn)

	s.Set([]byte{0}, []byte{0})
	s.Set([]byte{1}, []byte{1})
	s.Delete([]byte{1})
	ss, err := s.tree.Serialize()
	require.NoError(t, err)
	comm := s.GetRootCommitment()

	s2 := LoadStore(txn)
	ss2, err2 := s2.tree.Serialize()
	require.NoError(t, err2)
	assert.Equal(t, ss, ss2)
	assert.Equal(t, comm, s2.GetRootCommitment())
	assert.Equal(t, []byte{0}, s2.Get([]byte{0}))
	assert.False(t, s2.Has([]byte{1}))
	s2.Set([]byte{2}, []byte{2})

	ss2, err2 = s2.tree.Serialize()
	require.NoError(t, err2)
	assert.NotEqual(t, ss, ss2)
}
