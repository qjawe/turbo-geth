package trie

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/bits"
	"time"

	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/dbutils"
	"github.com/ledgerwatch/turbo-geth/common/hexutil"
	"github.com/ledgerwatch/turbo-geth/core/types/accounts"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/log"
	"github.com/ledgerwatch/turbo-geth/turbo/rlphacks"
	"github.com/ledgerwatch/turbo-geth/turbo/shards"
)

/*
**Theoretically:** "Merkle trie root calculation" starts from state, build from state keys - trie,
on each level of trie calculates intermediate hash of underlying data.

**Practically:** It can be implemented as "Preorder trie traversal" (Preorder - visit Root, visit Left, visit Right).
But, let's make couple observations to make traversal over huge state efficient.

**Observation 1:** `IntermediateHashOfAccountBucket` already stores state keys in sorted way.
Iteration over this bucket will retrieve keys in same order as "Preorder trie traversal".

**Observation 2:** each Eth block - changes not big part of state - it means most of Merkle trie intermediate hashes will not change.
It means we effectively can cache them. `IntermediateHashOfAccountBucket` stores "Intermediate hashes of all Merkle trie levels".
It also sorted and Iteration over `IntermediateHashOfAccountBucket` will retrieve keys in same order as "Preorder trie traversal".

**Implementation:** by opening 1 Cursor on state and 1 more Cursor on intermediate hashes bucket - we will receive data in
 order of "Preorder trie traversal". Cursors will only do "sequential reads" and "jumps forward" - been hardware-friendly.
1 stack keeps all accumulated hashes, when sub-trie traverse ends - all hashes pulled from stack -> hashed -> new hash puts on stack - it's hash of visited sub-trie (it emulates recursive nature of "Preorder trie traversal" algo).

Imagine that account with key 0000....00 (64 zeroes, 32 bytes of zeroes) changed.
Here is an example sequence which can be seen by running 2 Cursors:
```
00   // key which came from cache, can't use it - because account with this prefix changed
0000 // key which came from cache, can't use it - because account with this prefix changed
...
{30 zero bytes}00    // key which came from cache, can't use it - because account with this prefix changed
{30 zero bytes}0000  // Account which came from state, use it - calculate hash, jump to "next sub-trie"
{30 zero bytes}01    // key which came from cache, it is "next sub-trie", use it, jump to "next sub-trie"
{30 zero bytes}02    // key which came from cache, it is "next sub-trie", use it, jump to "next sub-trie"
...
{30 zero bytes}ff    // key which came from cache, it is "next sub-trie", use it, jump to "next sub-trie"
{29 zero bytes}01    // key which came from cache, it is "next sub-trie" (1 byte shorter key), use it, jump to "next sub-trie"
{29 zero bytes}02    // key which came from cache, it is "next sub-trie" (1 byte shorter key), use it, jump to "next sub-trie"
...
ff                   // key which came from cache, it is "next sub-trie" (1 byte shorter key), use it, jump to "next sub-trie"
nil                  // db returned nil - means no more keys there, done
```
On practice Trie is no full - it means after account key `{30 zero bytes}0000` may come `{5 zero bytes}01` and amount of iterations will not be big.

### Attack - by delete account with huge state

It's possible to create Account with very big storage (increase storage size during many blocks).
Then delete this account (SELFDESTRUCT).
 Naive storage deletion may take several minutes - depends on Disk speed - means every Eth client
 will not process any incoming block that time. To protect against this attack:
 PlainState, HashedState and IntermediateTrieHash buckets have "incarnations". Account entity has field "Incarnation" -
 just a digit which increasing each SELFDESTRUCT or CREATE2 opcodes. Storage key formed by:
 `{account_key}{incarnation}{storage_hash}`. And [turbo/trie/trie_root.go](../../turbo/trie/trie_root.go) has logic - every time
 when Account visited - we save it to `accAddrHashWithInc` variable and skip any Storage or IntermediateTrieHashes with another incarnation.
*/

// FlatDBTrieLoader reads state and intermediate trie hashes in order equal to "Preorder trie traversal"
// (Preorder - visit Root, visit Left, visit Right)
//
// It produces stream of values and send this stream to `defaultReceiver`
// It skips storage with incorrect incarnations
//
// Each intermediate hash key firstly pass to RetainDecider, only if it returns "false" - such IH can be used.
type FlatDBTrieLoader struct {
	logPrefix          string
	trace              bool
	rd                 RetainDecider
	accAddrHash        common.Hash // Concatenation of addrHash of the currently build account with its incarnation encoding
	accAddrHashWithInc [40]byte    // Concatenation of addrHash of the currently build account with its incarnation encoding

	ihSeek, accSeek, storageSeek []byte
	kHex, kHexS                  []byte
	// Storage item buffer
	storageKey   []byte
	storageValue []byte

	// Account item buffer
	accountKey   []byte
	accountValue accounts.Account
	hashValue    []byte

	receiver        StreamReceiver
	defaultReceiver *RootHashAggregator
	hc              HashCollector2
	shc             StorageHashCollector2
}

// RootHashAggregator - calculates Merkle trie root hash from incoming data stream
type RootHashAggregator struct {
	trace            bool
	wasIH            bool
	wasIHStorage     bool
	wasStorage       bool
	root             common.Hash
	hc               HashCollector2
	shc              StorageHashCollector2
	currStorage      bytes.Buffer // Current key for the structure generation algorithm, as well as the input tape for the hash builder
	succStorage      bytes.Buffer
	valueStorage     []byte       // Current value to be used as the value tape for the hash builder
	hashAccount      common.Hash  // Current value to be used as the value tape for the hash builder
	hashStorage      common.Hash  // Current value to be used as the value tape for the hash builder
	curr             bytes.Buffer // Current key for the structure generation algorithm, as well as the input tape for the hash builder
	succ             bytes.Buffer
	currAccK         []byte
	value            []byte   // Current value to be used as the value tape for the hash builder
	groups           []uint16 // `groups` parameter is the map of the stack. each element of the `groups` slice is a bitmask, one bit per element currently on the stack. See `GenStructStep` docs
	groupsStorage    []uint16 // `groups` parameter is the map of the stack. each element of the `groups` slice is a bitmask, one bit per element currently on the stack. See `GenStructStep` docs
	branchSet        []uint16
	branchSetStorage []uint16
	hb               *HashBuilder
	hashData         GenStructStepHashData
	a                accounts.Account
	leafData         GenStructStepLeafData
	accData          GenStructStepAccountData
}

func NewRootHashAggregator() *RootHashAggregator {
	return &RootHashAggregator{
		hb: NewHashBuilder(false),
	}
}

func NewFlatDBTrieLoader(logPrefix string) *FlatDBTrieLoader {
	return &FlatDBTrieLoader{
		logPrefix:       logPrefix,
		defaultReceiver: NewRootHashAggregator(),
	}
}

// Reset prepares the loader for reuse
func (l *FlatDBTrieLoader) Reset(rd RetainDecider, hc HashCollector2, shc StorageHashCollector2, trace bool) error {
	l.defaultReceiver.Reset(hc, shc, trace)
	l.hc = hc
	l.shc = shc
	l.receiver = l.defaultReceiver
	l.trace = trace
	l.ihSeek, l.accSeek, l.storageSeek, l.kHex, l.kHexS = make([]byte, 0, 128), make([]byte, 0, 128), make([]byte, 0, 128), make([]byte, 0, 128), make([]byte, 0, 128)
	l.rd = rd
	if l.trace {
		fmt.Printf("----------\n")
		fmt.Printf("CalcTrieRoot\n")
	}
	return nil
}

func (l *FlatDBTrieLoader) SetStreamReceiver(receiver StreamReceiver) {
	l.receiver = receiver
}

// CalcTrieRoot algo:
//	for iterateIHOfAccounts {
//		if isDenseSequence
//          goto SkipAccounts
//
//		for iterateAccounts from prevIH to currentIH {
//			use(account)
//			for iterateIHOfStorage within accountWithIncarnation{
//				if isDenseSequence
//					goto SkipStorage
//
//				for iterateStorage from prevIHOfStorage to currentIHOfStorage {
//					use(storage)
//				}
//            SkipStorage:
//				use(ihStorage)
//			}
//		}
//    SkipAccounts:
//		use(IH)
//	}
func (l *FlatDBTrieLoader) CalcTrieRoot(db ethdb.Database, prefix []byte, quit <-chan struct{}) (common.Hash, error) {
	var (
		tx ethdb.Tx
	)

	var txDB ethdb.DbWithPendingMutations
	var useExternalTx bool

	// If method executed within transaction - use it, or open new read transaction
	if hasTx, ok := db.(ethdb.HasTx); ok && hasTx.Tx() != nil {
		txDB = hasTx.(ethdb.DbWithPendingMutations)
		tx = hasTx.Tx()
		useExternalTx = true
	} else {
		var err error
		txDB, err = db.Begin(context.Background(), ethdb.RW)
		if err != nil {
			return EmptyRoot, err
		}

		defer txDB.Rollback()
		tx = txDB.(ethdb.HasTx).Tx()
	}

	accs, storages := NewStateCursor(tx.Cursor(dbutils.HashedAccountsBucket)), NewStateCursor(tx.Cursor(dbutils.HashedStorageBucket))
	ihAccC, ihStorageC := tx.Cursor(dbutils.IntermediateHashOfAccountBucket), tx.CursorDupSort(dbutils.IntermediateHashOfStorageBucket)

	var canUse = func(prefix []byte) bool { return !l.rd.Retain(prefix) }
	ih := IH(canUse, l.hc, ihAccC)
	ihStorage := IHStorage2(canUse, l.shc, ihStorageC)
	_ = storages

	ss := tx.CursorDupSort(dbutils.HashedStorageBucket)

	logEvery := time.NewTicker(30 * time.Second)
	defer logEvery.Stop()
	defer func(t time.Time) { fmt.Printf("trie_root.go:225: %s\n", time.Since(t)) }(time.Now())
	i1, i2, i3, i4 := 0, 0, 0, 0
	for ihK, ihV, err := ih.First(prefix); ; ihK, ihV, err = ih.Next() { // no loop termination is at he end of loop
		if err != nil {
			return EmptyRoot, err
		}
		i1++
		if ih.skipState {
			goto SkipAccounts
		}

		i2++
		for k, kHex, v, err1 := accs.Seek(ih.FirstNotCoveredPrefix()); k != nil; k, kHex, v, err1 = accs.Next() {
			if err1 != nil {
				return EmptyRoot, err1
			}
			if err = common.Stopped(quit); err != nil {
				return EmptyRoot, err
			}
			if keyIsBefore(ihK, kHex) || !bytes.HasPrefix(kHex, prefix) { // read all accounts until next IH
				break
			}
			if err = l.accountValue.DecodeForStorage(v); err != nil {
				return EmptyRoot, fmt.Errorf("fail DecodeForStorage: %w", err)
			}
			if err = l.receiver.Receive(AccountStreamItem, kHex, nil, &l.accountValue, nil, nil, 0); err != nil {
				return EmptyRoot, err
			}
			if l.accountValue.Incarnation == 0 {
				continue
			}
			copy(l.accAddrHashWithInc[:], k)
			binary.BigEndian.PutUint64(l.accAddrHashWithInc[32:], l.accountValue.Incarnation)
			accWithInc := l.accAddrHashWithInc[:]
			for ihKS, ihVS, err2 := ihStorage.SeekToAccount(accWithInc); ; ihKS, ihVS, err2 = ihStorage.Next() {
				if err2 != nil {
					return EmptyRoot, err2
				}

				i3++
				if ihStorage.skipState {
					goto SkipStorage
				}

				i4++
				for kS, vS, err3 := ss.SeekBothRange(accWithInc, ihStorage.FirstNotCoveredPrefix()); kS != nil; kS, vS, err3 = ss.NextDup() {
					if err3 != nil {
						return EmptyRoot, err3
					}
					hexutil.DecompressNibbles(vS[:32], &l.kHexS)
					if keyIsBefore(ihKS, l.kHexS) { // read until next IH
						break
					}
					if err = l.receiver.Receive(StorageStreamItem, accWithInc, l.kHexS, nil, vS[32:], nil, 0); err != nil {
						return EmptyRoot, err
					}
				}

			SkipStorage:
				if ihKS == nil { // Loop termination
					break
				}

				if err = l.receiver.Receive(SHashStreamItem, accWithInc, ihKS, nil, nil, ihVS, 0); err != nil {
					return EmptyRoot, err
				}
				if len(ihKS) == 0 { // means we just sent acc.storageRoot
					break
				}
			}

			select {
			default:
			case <-logEvery.C:
				l.logProgress(k, ihK)
			}
		}

	SkipAccounts:
		if ihK == nil { // Loop termination
			break
		}

		if err = l.receiver.Receive(AHashStreamItem, ihK, nil, nil, nil, ihV, 0); err != nil {
			return EmptyRoot, err
		}
	}

	if err := l.receiver.Receive(CutoffStreamItem, nil, nil, nil, nil, nil, len(prefix)); err != nil {
		return EmptyRoot, err
	}

	if !useExternalTx {
		_, err := txDB.Commit()
		if err != nil {
			return EmptyRoot, err
		}
	}
	fmt.Printf("%d,%d,%d,%d\n", ih.is, i2, ihStorage.is, i4)
	return l.receiver.Root(), nil
}

func collectAccHashRangesToLoad(canUse func(prefix []byte) bool, prefix []byte, cache *shards.StateCache, quit <-chan struct{}) ([][]byte, error) {
	var cur []byte
	prev := common.CopyBytes(prefix)
	seek := make([]byte, 0, 256)
	seek = append(seek, prefix...)
	ranges := [][]byte{}
	var k [64][]byte
	var branch [64]uint16
	var id, maxID [64]int8
	var lvl int
	var ok bool
	ihK, branches, _, _ := cache.AccountHashesSeek(prefix)
	//fmt.Printf("sibling: %x -> %x\n", seek, ihK)

GotItemFromCache:
	for { // go to sibling in cache
		if ihK == nil {
			ranges = append(ranges, common.CopyBytes(prev), nil)
			break
		}
		lvl = len(ihK)
		k[lvl], branch[lvl], id[lvl], maxID[lvl] = ihK, branches, int8(bits.TrailingZeros16(branches)), int8(bits.Len16(branches))

		if err := common.Stopped(quit); err != nil {
			return nil, err
		}
		if prefix != nil && !bytes.HasPrefix(k[lvl], prefix) {
			return nil, nil
		}

		for ; lvl > 0; lvl-- { // go to parent sibling in mem
			cur = append(append(cur[:0], k[lvl]...), 0)
			//fmt.Printf("iteration: %x, %b, %d, %d\n", k[lvl], branch[lvl], id[lvl], maxID[lvl])
			for ; id[lvl] <= maxID[lvl]; id[lvl]++ { // go to sibling
				if (uint16(1)<<id[lvl])&branch[lvl] == 0 {
					continue
				}

				cur[len(cur)-1] = uint8(id[lvl])
				//fmt.Printf("check: %x->%t\n", cur, canUse(cur))
				if canUse(cur) {
					prev = append(prev[:0], cur...)
					continue // cache item can be used and exists in cache, then just go to next sibling
				}
				ihK, branches, _, _, ok = cache.GetAccountHash(cur)
				//fmt.Printf("child: %x -> %t\n", cur, ok)
				if ok {
					continue GotItemFromCache
				}
				ranges = append(ranges, common.CopyBytes(prev), common.CopyBytes(cur))
			}
		}

		_ = dbutils.NextNibblesSubtree(k[1], &seek)
		ihK, branches, _, _ = cache.AccountHashesSeek(seek)
		//fmt.Printf("sibling: %x -> %x, %d, %d, %d\n", seek, ihK, lvl, id[lvl], maxID[lvl])
	}
	fmt.Printf("ranges: %d\n", len(ranges)/2)
	return ranges, nil
}

func collectStHashRangesToLoad(canUse func(prefix []byte) bool, accHash common.Hash, incarnation uint64, cache *shards.StateCache, quit <-chan struct{}) ([][]byte, error) {
	var cur []byte
	prev := []byte{}
	seek := make([]byte, 0, 256)
	ranges := [][]byte{}
	var k [64][]byte
	var branch [64]uint16
	var id, maxID [64]int8
	var lvl int
	var ok bool
	ihK, branches, _, _ := cache.StorageHashesSeek(accHash, incarnation, []byte{})
	//fmt.Printf("sibling: %x -> %x\n", seek, ihK)

GotItemFromCache:
	for { // go to sibling in cache
		if ihK == nil {
			ranges = append(ranges, common.CopyBytes(prev), nil)
			break
		}
		lvl = len(ihK)
		k[lvl], branch[lvl], id[lvl], maxID[lvl] = ihK, branches, int8(bits.TrailingZeros16(branches)), int8(bits.Len16(branches))

		if err := common.Stopped(quit); err != nil {
			return nil, err
		}

		for ; lvl > 0; lvl-- { // go to parent sibling in mem
			cur = append(append(cur[:0], k[lvl]...), 0)
			//fmt.Printf("iteration: %x, %b, %d, %d\n", k[lvl], branch[lvl], id[lvl], maxID[lvl])
			for ; id[lvl] <= maxID[lvl]; id[lvl]++ { // go to sibling
				if (uint16(1)<<id[lvl])&branch[lvl] == 0 {
					continue
				}

				cur[len(cur)-1] = uint8(id[lvl])
				//fmt.Printf("check: %x->%t\n", cur, canUse(cur))
				if canUse(cur) {
					prev = append(prev[:0], cur...)
					continue // cache item can be used and exists in cache, then just go to next sibling
				}
				ihK, branches, _, _, ok = cache.GetStorageHash(accHash, incarnation, cur)
				//fmt.Printf("child: %x -> %t\n", cur, ok)
				if ok {
					continue GotItemFromCache
				}
				ranges = append(ranges, common.CopyBytes(prev), common.CopyBytes(cur))
			}
		}

		_ = dbutils.NextNibblesSubtree(k[1], &seek)
		ihK, branches, _, _ = cache.StorageHashesSeek(accHash, incarnation, seek)
		//fmt.Printf("sibling: %x -> %x, %d, %d, %d\n", seek, ihK, lvl, id[lvl], maxID[lvl])
	}
	fmt.Printf("ranges: %d\n", len(ranges)/2)
	return ranges, nil
}

func loadAccIHToCache(ih ethdb.Cursor, prefix []byte, ranges [][]byte, cache *shards.StateCache, quit <-chan struct{}) error {
	for i := 0; i < len(ranges)/2; i++ {
		if err := common.Stopped(quit); err != nil {
			return err
		}
		from, to := ranges[i*2], ranges[i*2+1]
		for k, v, err := ih.Seek(from); k != nil; k, v, err = ih.Next() {
			if err != nil {
				return err
			}
			if keyIsBefore(to, k) || !bytes.HasPrefix(k, prefix) { // read all accounts until next IH
				break
			}
			newV := make([]common.Hash, len(v[4:])/common.HashLength)
			for i := 0; i < len(newV); i++ {
				newV[i].SetBytes(v[i*common.HashLength : (i+1)*common.HashLength])
			}
			cache.SetAccountHashesRead(k, binary.BigEndian.Uint16(v), binary.BigEndian.Uint16(v[2:]), newV)
		}
	}
	return nil
}

func loadAccsToCache(accs ethdb.Cursor, ranges [][]byte, cache *shards.StateCache, quit <-chan struct{}) ([][]byte, error) {
	var seek, to []byte
	var storageIHRanges [][]byte
	for i := 0; i < len(ranges)/2; i++ {
		if err := common.Stopped(quit); err != nil {
			return nil, err
		}
		p1 := ranges[i*2]
		if len(p1)%2 == 1 {
			p1 = append(p1, 0)
		}
		hexutil.CompressNibbles(p1, &seek)
		p2 := ranges[i*2+1]
		if len(p2)%2 == 1 {
			p2 = append(p2, 0)
		}
		hexutil.CompressNibbles(p2, &to)
		for k, v, err := accs.Seek(seek); k != nil; k, v, err = accs.Next() {
			if err != nil {
				return nil, err
			}
			if keyIsBefore(to, k) {
				break
			}

			var a accounts.Account
			if err := a.DecodeForStorage(v); err != nil {
				return nil, err
			}
			if _, ok := cache.GetAccountByHashedAddress(common.BytesToHash(k)); !ok {
				cache.DeprecatedSetAccountRead(common.BytesToHash(k), &a)
			}

			accWithInc := make([]byte, 40)
			copy(accWithInc, k)
			binary.BigEndian.PutUint64(accWithInc[32:], a.Incarnation)
			storageIHRanges = append(storageIHRanges, accWithInc)
		}
	}
	return storageIHRanges, nil
}

func collectAccRangesToLoad(canUse func(prefix []byte) bool, prefix []byte, cache *shards.StateCache, quit <-chan struct{}) ([][]byte, error) {
	var cur []byte
	prev := []byte{}
	seek := make([]byte, 0, 256)
	seek = append(seek, prefix...)
	ranges := [][]byte{}
	var k [64][]byte
	var branch, child [64]uint16
	var id, maxID [64]int8
	var lvl int
	var ok bool
	ihK, branches, children, _ := cache.AccountHashesSeek(prefix)
	//fmt.Printf("sibling: %x -> %x\n", seek, ihK)

GotItemFromCache:
	for { // go to sibling in cache
		if ihK == nil {
			ranges = append(ranges, common.CopyBytes(prev), nil)
			break
		}
		lvl = len(ihK)
		k[lvl], branch[lvl], child[lvl], id[lvl], maxID[lvl] = ihK, branches, children, int8(bits.TrailingZeros16(branches))-1, int8(bits.Len16(branches))

		if err := common.Stopped(quit); err != nil {
			return nil, err
		}
		if prefix != nil && !bytes.HasPrefix(k[lvl], prefix) {
			return nil, nil
		}

		for ; lvl > 0; lvl-- { // go to parent sibling in mem
			cur = append(append(cur[:0], k[lvl]...), 0)
			//fmt.Printf("iteration: %x, %b, %d, %d\n", k[lvl], branch[lvl], id[lvl], maxID[lvl])
			for id[lvl]++; id[lvl] <= maxID[lvl]; id[lvl]++ { // go to sibling
				if (uint16(1)<<id[lvl])&child[lvl] == 0 {
					continue
				}

				cur[len(cur)-1] = uint8(id[lvl])
				if (uint16(1)<<id[lvl])&branch[lvl] == 0 {
					if !cache.HasAccountWithInPrefix(cur) {
						ranges = append(ranges, common.CopyBytes(prev), common.CopyBytes(cur))
					}
					continue
				}

				//fmt.Printf("check: %x->%t\n", cur, canUse(cur))
				if canUse(cur) {
					prev = append(prev[:0], cur...)
					continue // cache item can be used and exists in cache, then just go to next sibling
				}
				ihK, branches, children, _, ok = cache.GetAccountHash(cur)
				//fmt.Printf("child: %x -> %t\n", cur, ok)
				if ok {
					continue GotItemFromCache
				}
				ranges = append(ranges, common.CopyBytes(prev), common.CopyBytes(cur))
			}
		}

		_ = dbutils.NextNibblesSubtree(k[1], &seek)
		ihK, branches, children, _ = cache.AccountHashesSeek(seek)
		//fmt.Printf("sibling: %x -> %x, %d, %d, %d\n", seek, ihK, lvl, id[lvl], maxID[lvl])
	}

	return ranges, nil
}

func (l *FlatDBTrieLoader) prep(accs, ihAcc ethdb.Cursor, prefix []byte, cache *shards.StateCache, quit <-chan struct{}) error {
	defer func(t time.Time) { fmt.Printf("trie_root.go:338: %s\n", time.Since(t)) }(time.Now())
	canUse := func(prefix []byte) bool { return !l.rd.Retain(prefix) }
	accIHRanges, err := collectAccHashRangesToLoad(canUse, prefix, cache, quit)
	if err != nil {
		return err
	}
	err = loadAccIHToCache(ihAcc, prefix, accIHRanges, cache, quit)
	if err != nil {
		return err
	}
	accPrefixes, err := collectAccRangesToLoad(canUse, prefix, cache, quit)
	if err != nil {
		return err
	}
	storageIHPrefixes, err := loadAccsToCache(accs, accPrefixes, cache, quit)
	if err != nil {
		return err
	}
	_ = storageIHPrefixes
	ihKSBuf := make([]byte, 256)
	if err := cache.WalkStorageHashes(func(addrHash common.Hash, incarnation uint64, locHashPrefix []byte, branchChildren uint16, children uint16, hashes []common.Hash) error {
		for i := 0; i < 16; i++ {
			if ((uint16(1) << i) & branchChildren) == 0 {
				continue
			}
			ihK := tmpMakeIHPrefix(addrHash, incarnation, locHashPrefix, uint8(i), ihKSBuf)
			if l.rd.Retain(ihK) {
				cache.SetStorageHashDelete(addrHash, incarnation, locHashPrefix, branchChildren, children, hashes)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (l *FlatDBTrieLoader) post(storages ethdb.CursorDupSort, prefix []byte, cache *shards.StateCache, quit <-chan struct{}) (common.Hash, error) {
	var prevIHK []byte
	//ihKSBuf := make([]byte, 256)
	firstNotCoveredPrefix := make([]byte, 0, 128)
	//lastPart := make([]byte, 0, 128)

	logEvery := time.NewTicker(30 * time.Second)
	defer logEvery.Stop()
	l.accSeek = make([]byte, 64)
	defer func(t time.Time) { fmt.Printf("trie_root.go:375: %s\n", time.Since(t)) }(time.Now())
	canUse := func(prefix []byte) bool { return !l.rd.Retain(prefix) }
	i1, i2, i3, i4 := 0, 0, 0, 0
	if err := cache.AccountHashes2(canUse, prefix, func(ihK []byte, ihV common.Hash) error {
		i1++
		if isDenseSequence(prevIHK, ihK) {
			goto SkipAccounts
		}

		if prevIHK == nil {
			l.accSeek = common.CopyBytes(prefix)
		} else {
			_ = dbutils.NextNibblesSubtree(prevIHK, &l.accSeek)
		}
		if len(l.accSeek)%2 == 1 {
			l.accSeek = append(l.accSeek, 0)
		}
		hexutil.CompressNibbles(l.accSeek, &l.accSeek)
		if len(prevIHK) > 0 && len(l.accSeek) == 0 {
			return nil
		}
		if err := cache.WalkAccounts(l.accSeek, func(addrHash common.Hash, acc *accounts.Account) (bool, error) {
			if err := common.Stopped(quit); err != nil {
				return false, err
			}
			i2++
			hexutil.DecompressNibbles(addrHash.Bytes(), &l.kHex)
			if keyIsBefore(ihK, l.kHex) || !bytes.HasPrefix(l.kHex, prefix) { // read all accounts until next IH
				return false, nil
			}
			l.accountValue.Copy(acc)
			if err := l.receiver.Receive(AccountStreamItem, l.kHex, nil, &l.accountValue, nil, nil, 0); err != nil {
				return false, err
			}
			if l.accountValue.Incarnation == 0 {
				return true, nil
			}
			copy(l.accAddrHashWithInc[:], addrHash.Bytes())
			binary.BigEndian.PutUint64(l.accAddrHashWithInc[32:], l.accountValue.Incarnation)
			l.accAddrHash.SetBytes(addrHash.Bytes())
			var prevIHKS []byte
			if err := cache.StorageHashes(l.accAddrHash, l.accountValue.Incarnation, func(ihKS []byte, h common.Hash) error {
				i3++
				if isDenseSequence(prevIHKS, ihKS) {
					goto SkipStorage
				}

				_ = dbutils.NextNibblesSubtree(prevIHKS, &firstNotCoveredPrefix)
				if len(firstNotCoveredPrefix)%2 == 1 {
					firstNotCoveredPrefix = append(firstNotCoveredPrefix, 0)
				}
				hexutil.CompressNibbles(firstNotCoveredPrefix, &l.storageSeek)
				if len(l.storageSeek) == 0 {
					l.storageSeek = []byte{0}
				}
				for kS, vS, err3 := storages.SeekBothRange(l.accAddrHashWithInc[:], l.storageSeek); kS != nil; kS, vS, err3 = storages.NextDup() {
					if err3 != nil {
						return err3
					}
					i4++
					hexutil.DecompressNibbles(vS[:32], &l.kHexS)
					if keyIsBefore(ihKS, l.kHexS) { // read until next IH
						break
					}
					if err := l.receiver.Receive(StorageStreamItem, l.accAddrHashWithInc[:], l.kHexS, nil, vS[32:], nil, 0); err != nil {
						return err
					}
				}

			SkipStorage:
				if len(ihKS) == 0 || !bytes.HasPrefix(ihKS, l.ihSeek) { // Loop termination
					return nil
				}

				if err := l.receiver.Receive(SHashStreamItem, l.accAddrHashWithInc[:], ihKS, nil, nil, h.Bytes(), 0); err != nil {
					return err
				}
				prevIHKS = ihKS
				return nil
			}); err != nil {
				return false, err
			}

			select {
			default:
			case <-logEvery.C:
				l.logProgress(addrHash.Bytes(), ihK)
			}
			return true, nil
		}); err != nil {
			return err
		}

	SkipAccounts:
		if len(ihK) == 0 { // Loop termination
			return nil
		}

		if err := l.receiver.Receive(AHashStreamItem, ihK, nil, nil, nil, ihV[:], 0); err != nil {
			return err
		}
		prevIHK = ihK
		return nil
	}); err != nil {
		return EmptyRoot, err
	}

	if err := l.receiver.Receive(CutoffStreamItem, nil, nil, nil, nil, nil, len(prefix)); err != nil {
		return EmptyRoot, err
	}
	fmt.Printf("%d,%d,%d,%d\n", i1, i2, i3, i4)
	return EmptyRoot, nil
}

func (l *FlatDBTrieLoader) CalcTrieRootOnCache(db ethdb.Database, prefix []byte, cache *shards.StateCache, quit <-chan struct{}) (common.Hash, error) {
	var (
		tx ethdb.Tx
	)

	var txDB ethdb.DbWithPendingMutations
	var useExternalTx bool

	// If method executed within transaction - use it, or open new read transaction
	if hasTx, ok := db.(ethdb.HasTx); ok && hasTx.Tx() != nil {
		txDB = hasTx.(ethdb.DbWithPendingMutations)
		tx = hasTx.Tx()
		useExternalTx = true
	} else {
		var err error
		txDB, err = db.Begin(context.Background(), ethdb.RW)
		if err != nil {
			return EmptyRoot, err
		}

		defer txDB.Rollback()
		tx = txDB.(ethdb.HasTx).Tx()
	}

	accsC, stC := tx.Cursor(dbutils.HashedAccountsBucket), tx.Cursor(dbutils.HashedStorageBucket)
	//accs, storages := NewStateCursor(tx.Cursor(dbutils.HashedAccountsBucket)), NewStateCursor(tx.Cursor(dbutils.HashedStorageBucket))
	ihAccC, ihStorageC := tx.Cursor(dbutils.IntermediateHashOfAccountBucket), tx.Cursor(dbutils.IntermediateHashOfStorageBucket)
	ss := tx.CursorDupSort(dbutils.HashedStorageBucket)
	//_ = storages
	_ = ihStorageC
	_ = stC

	if _, _, _, _, ok := cache.GetAccountHash(prefix); !ok { // first warmup
		if err := ethdb.ForEach(ihAccC, func(k, v []byte) (bool, error) {
			newV := make([]common.Hash, len(v[4:])/common.HashLength)
			for i := 0; i < len(newV); i++ {
				newV[i].SetBytes(v[i*common.HashLength : (i+1)*common.HashLength])
			}
			cache.SetAccountHashesRead(k, binary.BigEndian.Uint16(v), binary.BigEndian.Uint16(v[2:]), newV)
			return true, nil
		}); err != nil {
			return EmptyRoot, err
		}
	}

	if err := l.prep(accsC, ihAccC, prefix, cache, quit); err != nil {
		panic(err)
	}
	if _, err := l.post(ss, prefix, cache, quit); err != nil {
		panic(err)
	}
	fmt.Printf("alwx\n")
	if !useExternalTx {
		_, err := txDB.Commit()
		if err != nil {
			return EmptyRoot, err
		}
	}
	//fmt.Printf("%d,%d,%d,%d\n", i1, i2, i3, i4)
	return l.receiver.Root(), nil
}

func (l *FlatDBTrieLoader) CalcTrieRootOnCache2(cache *shards.StateCache) (common.Hash, error) {
	fmt.Printf("CalcTrieRootOnCache2\n")
	if err := cache.AccountHashes2(func(_ []byte) bool { return true }, []byte{}, func(ihK []byte, ihV common.Hash) error {
		if len(ihK) == 0 { // Loop termination
			return nil
		}
		if err := l.receiver.Receive(AHashStreamItem, ihK, nil, nil, nil, ihV[:], 0); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return EmptyRoot, err
	}

	if err := l.receiver.Receive(CutoffStreamItem, nil, nil, nil, nil, nil, 0); err != nil {
		return EmptyRoot, err
	}
	return l.receiver.Root(), nil
}

func (l *FlatDBTrieLoader) logProgress(accountKey, ihK []byte) {
	var k string
	if accountKey != nil {
		k = makeCurrentKeyStr(accountKey)
	} else if ihK != nil {
		k = makeCurrentKeyStr(ihK)
	}
	log.Info(fmt.Sprintf("[%s] Calculating Merkle root", l.logPrefix), "current key", k)
}

func (r *RootHashAggregator) RetainNothing(_ []byte) bool {
	return false
}

func (r *RootHashAggregator) Reset(hc HashCollector2, shc StorageHashCollector2, trace bool) {
	r.hc = hc
	r.shc = shc
	r.curr.Reset()
	r.succ.Reset()
	r.value = nil
	r.groups = r.groups[:0]
	r.branchSet = r.branchSet[:0]
	r.a.Reset()
	r.hb.Reset()
	r.wasIH = false
	r.currStorage.Reset()
	r.succStorage.Reset()
	r.valueStorage = nil
	r.wasIHStorage, r.wasStorage = false, false
	r.root = common.Hash{}
	r.trace = trace
	r.hb.trace = trace
}

func (r *RootHashAggregator) Receive(itemType StreamItem,
	accountKey []byte,
	storageKey []byte,
	accountValue *accounts.Account,
	storageValue []byte,
	hash []byte,
	cutoff int,
) error {
	//fmt.Printf("1: %d, %x, %x, %x\n", itemType, accountKey, storageKey, hash)
	switch itemType {
	case StorageStreamItem:
		if len(r.currAccK) == 0 {
			r.currAccK = append(r.currAccK[:0], accountKey...)
		}
		r.advanceKeysStorage(storageKey, true /* terminator */)
		if r.wasStorage || r.wasIHStorage {
			if err := r.genStructStorage(); err != nil {
				return err
			}
		}
		r.saveValueStorage(false, storageValue, hash)
	case SHashStreamItem:
		if len(storageKey) == 0 { // this is ready-to-use storage root - no reason to call GenStructStep, also GenStructStep doesn't support empty prefixes
			r.hb.hashStack = append(append(r.hb.hashStack, byte(80+common.HashLength)), hash...)
			r.hb.nodeStack = append(r.hb.nodeStack, nil)
			r.accData.FieldSet |= AccountFieldStorageOnly
			break
		}
		if len(r.currAccK) == 0 {
			r.currAccK = append(r.currAccK[:0], accountKey...)
		}
		r.advanceKeysStorage(storageKey, false /* terminator */)
		if r.wasStorage || r.wasIHStorage {
			if err := r.genStructStorage(); err != nil {
				return err
			}
		}
		r.saveValueStorage(true, storageValue, hash)
	case AccountStreamItem:
		r.advanceKeysAccount(accountKey, true /* terminator */)
		if r.curr.Len() > 0 && !r.wasIH {
			r.cutoffKeysStorage(0)
			if r.wasStorage || r.wasIHStorage {
				if err := r.genStructStorage(); err != nil {
					return err
				}
				r.currStorage.Reset()
				r.succStorage.Reset()
				r.wasIHStorage, r.wasStorage = false, false
				r.branchSetStorage = r.branchSetStorage[:0]
				r.groupsStorage = r.groupsStorage[:0]
				// There are some storage items
				r.accData.FieldSet |= AccountFieldStorageOnly
			}
		}
		r.currAccK = r.currAccK[:0]
		if r.curr.Len() > 0 {
			if err := r.genStructAccount(); err != nil {
				return err
			}
		}
		if err := r.saveValueAccount(false, accountValue, hash); err != nil {
			return err
		}
	case AHashStreamItem:
		r.advanceKeysAccount(accountKey, false /* terminator */)
		if r.curr.Len() > 0 && !r.wasIH {
			r.cutoffKeysStorage(0)
			if r.wasStorage || r.wasIHStorage {
				if err := r.genStructStorage(); err != nil {
					return err
				}
				r.currStorage.Reset()
				r.succStorage.Reset()
				r.branchSetStorage = r.branchSetStorage[:0]
				r.groupsStorage = r.groupsStorage[:0]
				r.wasIHStorage, r.wasStorage = false, false
				// There are some storage items
				r.accData.FieldSet |= AccountFieldStorageOnly
			}
		}
		r.currAccK = r.currAccK[:0]
		if r.curr.Len() > 0 {
			if err := r.genStructAccount(); err != nil {
				return err
			}
		}
		if err := r.saveValueAccount(true, accountValue, hash); err != nil {
			return err
		}
	case CutoffStreamItem:
		if r.trace {
			fmt.Printf("storage cuttoff %d\n", cutoff)
		}
		r.cutoffKeysAccount(cutoff)
		if r.curr.Len() > 0 && !r.wasIH {
			r.cutoffKeysStorage(0)
			if r.wasStorage || r.wasIHStorage {
				if err := r.genStructStorage(); err != nil {
					return err
				}
				r.currStorage.Reset()
				r.succStorage.Reset()
				r.wasIHStorage, r.wasStorage = false, false
				// There are some storage items
				r.accData.FieldSet |= AccountFieldStorageOnly
			}
		}
		if r.curr.Len() > 0 {
			if err := r.genStructAccount(); err != nil {
				return err
			}
		}
		if r.hb.hasRoot() {
			r.root = r.hb.rootHash()
		} else {
			r.root = EmptyRoot
		}
		r.groups = r.groups[:0]
		r.branchSet = r.branchSet[:0]
		r.groupsStorage = r.groupsStorage[:0]
		r.branchSetStorage = r.branchSetStorage[:0]
		r.hb.Reset()
		r.wasIH = false
		r.wasIHStorage = false
		r.wasStorage = false
		r.curr.Reset()
		r.succ.Reset()
		r.currStorage.Reset()
		r.succStorage.Reset()
	}
	return nil
}

func (r *RootHashAggregator) Result() SubTries {
	panic("don't call me")
}

func (r *RootHashAggregator) Root() common.Hash {
	return r.root
}

func (r *RootHashAggregator) advanceKeysStorage(k []byte, terminator bool) {
	r.currStorage.Reset()
	r.currStorage.Write(r.succStorage.Bytes())
	r.succStorage.Reset()
	// Transform k to nibbles, but skip the incarnation part in the middle
	r.succStorage.Write(k)
	if terminator {
		r.succStorage.WriteByte(16)
	}
}

func (r *RootHashAggregator) cutoffKeysStorage(cutoff int) {
	r.currStorage.Reset()
	r.currStorage.Write(r.succStorage.Bytes())
	r.succStorage.Reset()
	//if r.currStorage.Len() > 0 {
	//	r.succStorage.Write(r.currStorage.Bytes()[:cutoff-1])
	//	r.succStorage.WriteByte(r.currStorage.Bytes()[cutoff-1] + 1) // Modify last nibble in the incarnation part of the `currStorage`
	//}
}

func (r *RootHashAggregator) genStructStorage() error {
	var err error
	var data GenStructStepData
	if r.wasIHStorage {
		r.hashData.Hash = r.hashStorage
		data = &r.hashData
	} else {
		r.leafData.Value = rlphacks.RlpSerializableBytes(r.valueStorage)
		data = &r.leafData
	}
	r.groupsStorage, r.branchSetStorage, err = GenStructStep2(r.RetainNothing, r.currStorage.Bytes(), r.succStorage.Bytes(), r.hb, func(keyHex []byte, set uint16, branchSet uint16, hashes []byte, rootHash []byte) error {
		return r.shc(r.currAccK, keyHex, set, branchSet, hashes, rootHash)
	}, data, r.groupsStorage, r.branchSetStorage, r.trace)
	if err != nil {
		return err
	}
	return nil
}

func (r *RootHashAggregator) saveValueStorage(isIH bool, v, h []byte) {
	// Remember the current value
	r.wasIHStorage = isIH
	r.wasStorage = !isIH
	r.valueStorage = nil
	if isIH {
		r.hashStorage.SetBytes(h)
	} else {
		r.valueStorage = v
	}
}

func (r *RootHashAggregator) advanceKeysAccount(k []byte, terminator bool) {
	r.curr.Reset()
	r.curr.Write(r.succ.Bytes())
	r.succ.Reset()
	r.succ.Write(k)
	if terminator {
		r.succ.WriteByte(16)
	}
}

func (r *RootHashAggregator) cutoffKeysAccount(cutoff int) {
	r.curr.Reset()
	r.curr.Write(r.succ.Bytes())
	r.succ.Reset()
	if r.curr.Len() > 0 && cutoff > 0 {
		r.succ.Write(r.curr.Bytes()[:cutoff-1])
		r.succ.WriteByte(r.curr.Bytes()[cutoff-1] + 1) // Modify last nibble before the cutoff point
	}
}

func (r *RootHashAggregator) genStructAccount() error {
	var data GenStructStepData
	if r.wasIH {
		r.hashData.Hash = r.hashAccount
		//copy(r.hashData.Hash[:], r.value)
		data = &r.hashData
	} else {
		r.accData.Balance.Set(&r.a.Balance)
		if r.a.Balance.Sign() != 0 {
			r.accData.FieldSet |= AccountFieldBalanceOnly
		}
		r.accData.Nonce = r.a.Nonce
		if r.a.Nonce != 0 {
			r.accData.FieldSet |= AccountFieldNonceOnly
		}
		r.accData.Incarnation = r.a.Incarnation
		data = &r.accData
	}
	r.wasIHStorage = false
	r.currStorage.Reset()
	r.succStorage.Reset()
	var err error
	if r.groups, r.branchSet, err = GenStructStep2(r.RetainNothing, r.curr.Bytes(), r.succ.Bytes(), r.hb, r.hc, data, r.groups, r.branchSet, r.trace); err != nil {
		return err
	}
	r.accData.FieldSet = 0
	return nil
}

func (r *RootHashAggregator) saveValueAccount(isIH bool, v *accounts.Account, h []byte) error {
	r.wasStorage = false
	r.wasIH = isIH
	if isIH {
		r.hashAccount.SetBytes(h)
		return nil
	}
	r.a.Copy(v)
	// Place code on the stack first, the storage will follow
	if !r.a.IsEmptyCodeHash() {
		// the first item ends up deepest on the stack, the second item - on the top
		r.accData.FieldSet |= AccountFieldCodeOnly
		if err := r.hb.hash(r.a.CodeHash[:]); err != nil {
			return err
		}
	}
	return nil
}

type CanUse func([]byte) bool // returns false - if element must be skipped

const IHDupKeyLen = 2 * (common.HashLength + common.IncarnationLength)

// IHCursor - holds logic related to iteration over IH bucket
type IHCursor struct {
	skipState                  bool
	is, lvl                    int
	k, v                       [64][]byte
	deleted                    [64]bool
	childID, maxHashID, hashID [64]int16
	branches, children         [64]uint16

	c                     ethdb.Cursor
	hc                    HashCollector2
	seek, prev, cur, next []byte
	prefix                []byte

	firstNotCoveredPrefix []byte
	canUse                func(prefix []byte) bool

	kBuf []byte
}

func IH(canUse func(prefix []byte) bool, hc HashCollector2, c ethdb.Cursor) *IHCursor {
	ih := &IHCursor{c: c, canUse: canUse,
		firstNotCoveredPrefix: make([]byte, 0, 64),
		next:                  make([]byte, 64),
		hc:                    hc,
	}
	return ih
}

func (c *IHCursor) FirstNotCoveredPrefix() []byte {
	if len(c.prev) > 0 {
		_ = dbutils.NextNibblesSubtree(c.prev, &c.firstNotCoveredPrefix)
	} else {
		c.firstNotCoveredPrefix = append(c.firstNotCoveredPrefix[:0], c.seek...)
	}
	if len(c.firstNotCoveredPrefix)%2 == 1 {
		c.firstNotCoveredPrefix = append(c.firstNotCoveredPrefix, 0)
	}
	hexutil.CompressNibbles(c.firstNotCoveredPrefix, &c.firstNotCoveredPrefix)
	return c.firstNotCoveredPrefix
}

func (c *IHCursor) First(prefix []byte) (k, v []byte, err error) {
	c.skipState = false
	c.prev = append(c.prev[:0], c.cur...)
	c.prefix = prefix
	c.seek = prefix
	ok := c._goToChildInDB(prefix)
	if !ok || c.k[c.lvl] == nil {
		c.cur = nil
		c.skipState = isDenseSequence(c.prev, c.cur)
		return nil, nil, nil
	}
	c.kBuf = append(append(c.kBuf[:0], c.k[c.lvl]...), uint8(c.childID[c.lvl]))
	if c.canUse(c.kBuf) {
		c.cur = append(c.cur[:0], c.kBuf...)
		c.skipState = isDenseSequence(c.prev, c.cur)
		return c.cur, c._hash(c.hashID[c.lvl]), nil
	}
	err = c._deleteCurrent()
	if err != nil {
		return []byte{}, nil, err
	}

	return c._next()
}

func (c *IHCursor) _deleteCurrent() error {
	if c.deleted[c.lvl] {
		return nil
	}
	if err := c.hc(c.k[c.lvl], 0, 0, nil, nil); err != nil {
		return err
	}
	c.deleted[c.lvl] = true
	return nil
}

func (c *IHCursor) Next() (k, v []byte, err error) {
	c.skipState = false
	c.prev = append(c.prev[:0], c.cur...)
	_ = c._nextSiblingInMem() || c._nextSiblingOfParentInMem() || c._nextSiblingInDB()

	if c.k[c.lvl] == nil {
		c.cur = nil
		c.skipState = isDenseSequence(c.prev, c.cur)
		return nil, nil, nil
	}
	c.kBuf = append(append(c.kBuf[:0], c.k[c.lvl]...), uint8(c.childID[c.lvl]))
	if c.canUse(c.kBuf) {
		c.cur = append(c.cur[:0], c.kBuf...)
		c.skipState = isDenseSequence(c.prev, c.cur) || c._complexSkpState()
		return c.cur, c._hash(c.hashID[c.lvl]), nil
	}
	err = c._deleteCurrent()
	if err != nil {
		return []byte{}, nil, err
	}

	return c._next()
}

func (c *IHCursor) _nextSiblingInMem() bool {
	if c.hashID[c.lvl] >= c.maxHashID[c.lvl] {
		return false
	}
	c.childID[c.lvl]++
	for c.childID[c.lvl] < 16 && ((uint16(1)<<c.childID[c.lvl])&c.branches[c.lvl]) == 0 {
		c.childID[c.lvl]++
	}
	c.hashID[c.lvl]++
	return true
}

func (c *IHCursor) _nextSiblingOfParentInMem() bool {
	for c.lvl > 1 {
		c.lvl--
		if c._nextSiblingInMem() {
			return true
		}
	}
	return false
}

func (c *IHCursor) _nextSiblingInDB() bool {
	ok := dbutils.NextNibblesSubtree(c.k[1], &c.next)
	if !ok {
		c.k[c.lvl] = nil
		return false
	}
	c.is++
	k, v, err := c.c.Seek(c.next)
	if err != nil {
		panic(err)
	}
	if k == nil || !bytes.HasPrefix(k, c.prefix) {
		c.k[c.lvl] = nil
		return false
	}
	c._parse(k, v)
	c._nextSiblingInMem()
	return true
}

func (c *IHCursor) _parse(k, v []byte) {
	c.lvl = len(k)
	c.k[c.lvl] = k
	c.deleted[c.lvl] = false
	c.branches[c.lvl], c.children[c.lvl] = binary.BigEndian.Uint16(v), binary.BigEndian.Uint16(v[2:])
	c.v[c.lvl] = v[4:]
	c.hashID[c.lvl], c.maxHashID[c.lvl] = -1, int16(bits.OnesCount16(c.branches[c.lvl])-1)
	c.childID[c.lvl] = int16(bits.TrailingZeros16(c.branches[c.lvl]) - 1)
	if len(c.k[c.lvl]) == 0 { // root record, firstly storing root hash
		c.v[c.lvl] = c.v[c.lvl][32:]
	}
}

func (c *IHCursor) _goToChildInDB(prefix []byte) bool {
	var k, v []byte
	var err error
	if len(prefix) == 0 {
		k, v, err = c.c.First()
	} else {
		// optimistic .Next call, can use result in 2 cases:
		// - no child found, means: len(k) <= c.lvl
		// - looking for first child, means: c.childID[c.lvl] <= int16(bits.TrailingZeros16(c.branches[c.lvl]))
		// otherwise do .Seek call
		k, v, err = c.c.Next()
		if err != nil {
			panic(err)
		}
		if len(k) > c.lvl && c.childID[c.lvl] > int16(bits.TrailingZeros16(c.branches[c.lvl])) {
			c.is++
			k, v, err = c.c.Seek(prefix)
		}
	}
	if err != nil {
		panic(err)
	}
	if k == nil || !bytes.HasPrefix(k, prefix) {
		//fmt.Printf("_goToChildInDB out of prefix: %x -> %x\n", prefix, k)
		return false
	}
	c._parse(k, v)
	c._nextSiblingInMem()
	return true
}

func (c *IHCursor) _hash(i int16) []byte {
	return c.v[c.lvl][common.HashLength*i : common.HashLength*(i+1)]
}

func (c *IHCursor) _complexSkpState() bool {
	// experimental example of - how can skip state by looking to 'children' bitmap
	return false
	//if len(c.prev) == len(c.cur) && bytes.Equal(c.prev[:len(c.prev)-1], c.cur[:len(c.cur)-1]) {
	//	mask := uint16(0)
	//	foundThings := false
	//	for i := int16(c.prev[len(c.prev)-1]) + 1; i < c.childID[c.lvl]; i++ {
	//		c.kBuf[len(c.kBuf)-1] = uint8(i)
	//		if !c.canUse(c.kBuf) {
	//			foundThings = true
	//			break
	//		}
	//		mask |= uint16(1) << i
	//	}
	//	return !foundThings && c.children[c.lvl]&mask == 0
	//}
	//return false
}

func (c *IHCursor) _next() (k, v []byte, err error) {
	c.next = append(append(c.next[:0], c.k[c.lvl]...), byte(c.childID[c.lvl]))
	_ = c._goToChildInDB(c.next) || c._nextSiblingInMem() || c._nextSiblingOfParentInMem() || c._nextSiblingInDB()

	for {
		if c.k[c.lvl] == nil {
			c.cur = nil
			c.skipState = isDenseSequence(c.prev, c.cur)
			return nil, nil, nil
		}
		c.kBuf = append(append(c.kBuf[:0], c.k[c.lvl]...), uint8(c.childID[c.lvl]))
		if c.canUse(c.kBuf) {
			c.cur = append(c.cur[:0], c.kBuf...)
			c.skipState = isDenseSequence(c.prev, c.cur) || c._complexSkpState()
			return c.cur, c._hash(c.hashID[c.lvl]), nil
		}
		err = c._deleteCurrent()
		if err != nil {
			return []byte{}, nil, err
		}

		c.next = append(append(c.next[:0], c.k[c.lvl]...), byte(c.childID[c.lvl]))
		_ = c._goToChildInDB(c.next) || c._nextSiblingInMem() || c._nextSiblingOfParentInMem() || c._nextSiblingInDB()
	}
}

// IHCursor - holds logic related to iteration over IH bucket
type StorageIHCursor struct {
	is, lvl                    int
	k, v                       [64][]byte
	deleted                    [64]bool
	childID, maxHashID, hashID [64]int16
	branches, children         [64]uint16

	c         ethdb.Cursor
	shc       StorageHashCollector2
	prev, cur []byte
	seek      []byte
	root      []byte

	next                  []byte
	firstNotCoveredPrefix []byte
	canUse                func(prefix []byte) bool
	skipState             bool

	accWithInc []byte
	kBuf       []byte
}

func IHStorage2(canUse func(prefix []byte) bool, shc StorageHashCollector2, c ethdb.Cursor) *StorageIHCursor {
	ih := &StorageIHCursor{c: c, canUse: canUse,
		firstNotCoveredPrefix: make([]byte, 0, 64), next: make([]byte, 64),
		shc: shc,
	}
	return ih
}

func (c *StorageIHCursor) PrevKey() []byte {
	return c.prev
}

func (c *StorageIHCursor) FirstNotCoveredPrefix() []byte {
	_ = dbutils.NextNibblesSubtree(c.prev, &c.firstNotCoveredPrefix)
	if len(c.firstNotCoveredPrefix) == 0 {
		c.firstNotCoveredPrefix = append(c.firstNotCoveredPrefix, 0, 0)
	}
	if len(c.firstNotCoveredPrefix)%2 == 1 {
		c.firstNotCoveredPrefix = append(c.firstNotCoveredPrefix, 0)
	}
	hexutil.CompressNibbles(c.firstNotCoveredPrefix, &c.firstNotCoveredPrefix)
	return c.firstNotCoveredPrefix
}

func (c *StorageIHCursor) SeekToAccount(prefix []byte) (k, v []byte, err error) {
	c.accWithInc = prefix
	hexutil.DecompressNibbles(c.accWithInc, &c.kBuf)
	c.seek = append(c.seek[:0], c.accWithInc...)
	c.skipState = false
	c.prev = c.cur
	ok := c._goToChildInDB(prefix)
	if !ok || c.k[c.lvl] == nil {
		c.cur = nil
		c.skipState = isDenseSequence(c.prev, c.cur)
		return nil, nil, nil
	}
	if c.root != nil { // check if acc.storageRoot can be used
		root := c.root
		c.root = nil
		if c.canUse(c.kBuf) { // if rd allow us, return. otherwise delete and go ahead.
			c.cur = c.k[c.lvl]
			c.skipState = true
			return c.cur, root, nil
		}
		c._nextSiblingInMem()
	}

	c.kBuf = append(append(c.kBuf[:80], c.k[c.lvl]...), uint8(c.childID[c.lvl]))
	if c.canUse(c.kBuf) {
		c.cur = common.CopyBytes(c.kBuf[80:])
		c.skipState = isDenseSequence(c.prev, c.cur)
		return c.cur, c._hash(c.hashID[c.lvl]), nil
	}
	err = c._deleteCurrent()
	if err != nil {
		return []byte{}, nil, err
	}
	return c._next()
}

func (c *StorageIHCursor) _parse(k, v []byte) {
	c.lvl = len(k) - 40
	c.k[c.lvl] = k[40:]
	c.deleted[c.lvl] = false
	c.branches[c.lvl] = binary.BigEndian.Uint16(v)
	c.children[c.lvl] = binary.BigEndian.Uint16(v[2:])
	c.hashID[c.lvl] = -1
	c.maxHashID[c.lvl] = int16(bits.OnesCount16(c.branches[c.lvl]) - 1)
	c.childID[c.lvl] = int16(bits.TrailingZeros16(c.branches[c.lvl]) - 1)
	c.v[c.lvl] = v[4:]
	if len(c.k[c.lvl]) == 0 { // root record, firstly storing root hash
		c.root = c.v[c.lvl][:32]
		c.v[c.lvl] = c.v[c.lvl][32:]
	}
}

func (c *StorageIHCursor) _complexSkpState() bool {
	return false
	//if len(c.prev) == len(c.cur) && bytes.Equal(c.prev[:len(c.prev)-1], c.cur[:len(c.cur)-1]) {
	//	mask := uint16(0)
	//	foundThings := false
	//	for i := int16(c.prev[len(c.prev)-1]) + 1; i < c.childID[c.lvl]; i++ {
	//		c.kBuf[len(c.kBuf)-1] = uint8(i)
	//		if !c.canUse(c.kBuf) {
	//			foundThings = true
	//			break
	//		}
	//		mask |= uint16(1) << i
	//	}
	//	return !foundThings && c.children[c.lvl]&mask == 0
	//}
	//return false
}

func (c *StorageIHCursor) _deleteCurrent() error {
	if c.deleted[c.lvl] {
		return nil
	}
	if err := c.shc(c.accWithInc, c.k[c.lvl], 0, 0, nil, nil); err != nil {
		return err
	}
	c.deleted[c.lvl] = true
	return nil
}

func (c *StorageIHCursor) Next() (k, v []byte, err error) {
	c.skipState = false
	c.prev = c.cur
	_ = c._nextSiblingInMem() || c._nextSiblingOfParentInMem() || c._nextSiblingInDB()

	if c.k[c.lvl] == nil {
		c.cur = nil
		c.skipState = isDenseSequence(c.prev, c.cur)
		return nil, nil, nil
	}
	c.kBuf = append(append(c.kBuf[:80], c.k[c.lvl]...), uint8(c.childID[c.lvl]))
	if c.canUse(c.kBuf) {
		c.cur = common.CopyBytes(c.kBuf[80:])
		c.skipState = isDenseSequence(c.prev, c.cur) || c._complexSkpState()
		return c.cur, c._hash(c.hashID[c.lvl]), nil
	}
	err = c._deleteCurrent()
	if err != nil {
		return []byte{}, nil, err
	}

	return c._next()
}

func (c *StorageIHCursor) _nextSiblingInMem() bool {
	if c.hashID[c.lvl] >= c.maxHashID[c.lvl] {
		return false
	}
	c.childID[c.lvl]++
	for c.childID[c.lvl] < 16 && ((uint16(1)<<c.childID[c.lvl])&c.branches[c.lvl] == 0) {
		c.childID[c.lvl]++
	}
	c.hashID[c.lvl]++
	return true
}

func (c *StorageIHCursor) _nextSiblingOfParentInMem() bool {
	for c.lvl > 0 {
		c.lvl--
		if c._nextSiblingInMem() {
			return true
		}
	}
	return false
}

func (c *StorageIHCursor) _nextSiblingInDB() bool {
	ok := dbutils.NextNibblesSubtree(c.k[c.lvl], &c.next)
	if !ok {
		c.k[c.lvl] = nil
		return false
	}
	c.is++
	c.seek = append(c.seek[:40], c.next...)
	k, v, err := c.c.Seek(c.seek)
	if err != nil {
		panic(err)
	}
	if k == nil || !bytes.HasPrefix(k, c.accWithInc) {
		c.k[c.lvl] = nil
		return false
	}
	c._parse(k, v)
	c._nextSiblingInMem()
	return true
}

func (c *StorageIHCursor) _goToChildInDB(prefix []byte) bool {
	var k, v []byte
	var err error
	if len(prefix) == 40 {
		c.is++
		k, v, err = c.c.Seek(prefix)
	} else {
		// optimistic .Next call, can use result in 2 cases:
		// - no child found, means: len(k) <= c.lvl
		// - looking for first child, means: c.childID[c.lvl] <= int16(bits.TrailingZeros16(c.branches[c.lvl]))
		// otherwise do .Seek call
		k, v, err = c.c.Next()
		if err != nil {
			panic(err)
		}
		if len(k) > c.lvl && c.childID[c.lvl] > int16(bits.TrailingZeros16(c.branches[c.lvl])) {
			c.is++
			k, v, err = c.c.Seek(prefix)
		}
	}
	if err != nil {
		panic(err)
	}
	if k == nil || !bytes.HasPrefix(k, prefix) {
		//fmt.Printf("_goToChildInDB out of prefix: %x -> %x\n", prefix, k)
		return false
	}
	c._parse(k, v)
	if len(c.k[c.lvl]) > 0 { // root record, firstly storing root hash
		c._nextSiblingInMem()
	}
	return true
}

func (c *StorageIHCursor) _hash(i int16) []byte {
	return c.v[c.lvl][common.HashLength*i : common.HashLength*(i+1)]
}

func (c *StorageIHCursor) _next() (k, v []byte, err error) {
	c.seek = append(append(c.seek[:40], c.k[c.lvl]...), byte(c.childID[c.lvl]))
	_ = c._goToChildInDB(c.seek) || c._nextSiblingInMem() || c._nextSiblingOfParentInMem() || c._nextSiblingInDB()

	for {
		if c.k[c.lvl] == nil {
			c.cur = nil
			c.skipState = isDenseSequence(c.prev, c.cur)
			return nil, nil, nil
		}

		c.kBuf = append(append(c.kBuf[:80], c.k[c.lvl]...), uint8(c.childID[c.lvl]))
		if c.canUse(c.kBuf) {
			c.cur = common.CopyBytes(c.kBuf[80:])
			c.skipState = isDenseSequence(c.prev, c.cur) || c._complexSkpState()
			return c.cur, c._hash(c.hashID[c.lvl]), nil
		}
		err = c._deleteCurrent()
		if err != nil {
			return []byte{}, nil, err
		}

		c.seek = append(append(c.seek[:40], c.k[c.lvl]...), byte(c.childID[c.lvl]))
		_ = c._goToChildInDB(c.seek) || c._nextSiblingInMem() || c._nextSiblingOfParentInMem() || c._nextSiblingInDB()
	}
}

/*
	Dense Sequence - if between 2 IH records not possible insert any state record - then they form "dense sequence"
	If 2 IH records form Dense Sequence - then no reason to iterate over state - just use IH one after another
	Example1:
		1234
		1235
	Example2:
		12ff
		13
	Example3:
		12ff
		13000000
	If 2 IH records form "sequence" then it can be consumed without moving StateCursor
*/
func isDenseSequence(prev []byte, next []byte) bool {
	isSequence := false
	if len(prev) == 0 && len(next) == 0 {
		return false
	}
	ok := dbutils.NextNibblesSubtree(prev, &isSequenceBuf)
	if len(prev) > 0 && !ok {
		return true
	}
	if bytes.HasPrefix(next, isSequenceBuf) {
		tail := next[len(isSequenceBuf):] // if tail has only zeroes, then no state records can be between fstl.nextHex and fstl.ihK
		isSequence = true
		for _, n := range tail {
			if n != 0 {
				isSequence = false
				break
			}
		}
	}

	return isSequence
}

var isSequenceBuf = make([]byte, 256)

type StateCursor struct {
	c    ethdb.Cursor
	kHex []byte
}

func NewStateCursor(c ethdb.Cursor) *StateCursor {
	return &StateCursor{c: c}
}

func (c *StateCursor) Seek(seek []byte) ([]byte, []byte, []byte, error) {
	k, v, err := c.c.Seek(seek)
	if err != nil {
		return []byte{}, nil, nil, err
	}

	hexutil.DecompressNibbles(k, &c.kHex)
	return k, c.kHex, v, nil
}

func (c *StateCursor) Next() ([]byte, []byte, []byte, error) {
	k, v, err := c.c.Next()
	if err != nil {
		return []byte{}, nil, nil, err
	}

	hexutil.DecompressNibbles(k, &c.kHex)
	return k, c.kHex, v, nil
}

func nextAccount(in, out []byte) bool {
	copy(out, in)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] != 255 {
			out[i]++
			return true
		}
		out[i] = 0
	}
	return false
}

func nextAccountHex(in, out []byte) bool {
	copy(out, in)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] != 15 {
			out[i]++
			return true
		}
		out[i] = 0
	}
	return false
}

// keyIsBefore - kind of bytes.Compare, but nil is the last key. And return
func keyIsBeforeOrEqual(k1, k2 []byte) (bool, []byte) {
	if k1 == nil {
		return false, k2
	}

	if k2 == nil {
		return true, k1
	}

	switch bytes.Compare(k1, k2) {
	case -1, 0:
		return true, k1
	default:
		return false, k2
	}
}

// keyIsBefore - kind of bytes.Compare, but nil is the last key. And return
func keyIsBefore(k1, k2 []byte) bool {
	if k1 == nil {
		return false
	}

	if k2 == nil {
		return true
	}

	switch bytes.Compare(k1, k2) {
	case -1:
		return true
	default:
		return false
	}
}

func tmpMakeIHPrefix(addrHash common.Hash, incarnation uint64, prefix []byte, branchChild uint8, buf []byte) []byte {
	hexutil.DecompressNibbles(addrHash.Bytes(), &buf)
	incBuf := buf[80:96]
	binary.BigEndian.PutUint64(incBuf, incarnation)
	to := buf[64:]
	hexutil.DecompressNibbles(incBuf, &to)
	l := 80 + len(prefix)
	buf = buf[:l]
	copy(buf[80:l], prefix)
	buf = append(buf, branchChild)
	return common.CopyBytes(buf)
}
