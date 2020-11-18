package stagedsync

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/changeset"
	"github.com/ledgerwatch/turbo-geth/common/dbutils"
	"github.com/ledgerwatch/turbo-geth/common/etl"
	"github.com/ledgerwatch/turbo-geth/core"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/ethdb/bitmapdb"
	"github.com/ledgerwatch/turbo-geth/log"
)

func SpawnAccountHistoryIndex(s *StageState, db ethdb.Database, tmpdir string, quitCh <-chan struct{}) error {
	var tx ethdb.DbWithPendingMutations
	var useExternalTx bool
	if hasTx, ok := db.(ethdb.HasTx); ok && hasTx.Tx() != nil {
		tx = db.(ethdb.DbWithPendingMutations)
		useExternalTx = true
	} else {
		var err error
		tx, err = db.Begin(context.Background(), ethdb.RW)
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}

	executionAt, err := s.ExecutionAt(tx)
	logPrefix := s.state.LogPrefix()
	if err != nil {
		return fmt.Errorf("%s: logs index: getting last executed block: %w", logPrefix, err)
	}
	if executionAt == s.BlockNumber {
		s.Done()
		return nil
	}

	start := s.BlockNumber
	if start > 0 {
		start++
	}

	var startChangeSetsLookupAt uint64
	if s.BlockNumber > 0 {
		startChangeSetsLookupAt = s.BlockNumber + 1
	}
	stopChangeSetsLookupAt := executionAt + 1

	if err := promoteHistory(logPrefix, tx, dbutils.PlainAccountChangeSetBucket, startChangeSetsLookupAt, stopChangeSetsLookupAt, tmpdir, quitCh); err != nil {
		return err
	}

	if err := promoteHistory(logPrefix, tx, dbutils.PlainStorageChangeSetBucket, startChangeSetsLookupAt, stopChangeSetsLookupAt, tmpdir, quitCh); err != nil {
		return err
	}

	if err := s.DoneAndUpdate(tx, executionAt); err != nil {
		return err
	}

	if !useExternalTx {
		if _, err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func promoteHistory(logPrefix string, db ethdb.Database, changesetBucket string, start, stop uint64, tmpdir string, quit <-chan struct{}) error {
	logEvery := time.NewTicker(30 * time.Second)
	defer logEvery.Stop()

	updates := map[string]*roaring.Bitmap{}
	creates := map[string]*roaring.Bitmap{}
	checkFlushEvery := time.NewTicker(logIndicesCheckSizeEvery)
	defer checkFlushEvery.Stop()

	collectorUpdates := etl.NewCollector(tmpdir, etl.NewSortableBuffer(etl.BufferOptimalSize))
	collectorCreates := etl.NewCollector(tmpdir, etl.NewSortableBuffer(etl.BufferOptimalSize))

	if err := changeset.Walk(db, changesetBucket, dbutils.EncodeBlockNumber(start), 0, func(blockN uint64, k, v []byte) (bool, error) {
		if blockN >= stop {
			return false, nil
		}
		if err := common.Stopped(quit); err != nil {
			return false, err
		}
		blockNum := binary.BigEndian.Uint64(k[:8])

		select {
		default:
		case <-logEvery.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			log.Info(fmt.Sprintf("[%s] Progress", logPrefix), "number", blockNum, "alloc", common.StorageSize(m.Alloc), "sys", common.StorageSize(m.Sys))
		case <-checkFlushEvery.C:
			if needFlush(updates, logIndicesMemLimit) {
				if err := flushBitmaps(collectorUpdates, updates); err != nil {
					return false, err
				}
				updates = map[string]*roaring.Bitmap{}
			}

			if needFlush(creates, logIndicesMemLimit) {
				if err := flushBitmaps(collectorCreates, creates); err != nil {
					return false, err
				}
				creates = map[string]*roaring.Bitmap{}
			}
		}

		if len(v) == 0 {
			creates[string(k)].Add(uint32(blockNum))
		} else {
			updates[string(k)].Add(uint32(blockNum))
		}

		return false, nil
	}); err != nil {
		return err
	}

	if err := flushBitmaps(collectorUpdates, updates); err != nil {
		return err
	}
	if err := flushBitmaps(collectorCreates, creates); err != nil {
		return err
	}

	var currentBitmap = roaring.New()
	var buf = bytes.NewBuffer(nil)

	var loaderFunc = func(k []byte, v []byte, table etl.CurrentTableReader, next etl.LoadNextFunc) error {
		lastChunkKey := make([]byte, len(k)+4)
		copy(lastChunkKey, k)
		binary.BigEndian.PutUint32(lastChunkKey[len(k):], ^uint32(0))
		lastChunkBytes, err := table.Get(lastChunkKey)
		if err != nil && !errors.Is(err, ethdb.ErrKeyNotFound) {
			return fmt.Errorf("%s: find last chunk failed: %w", logPrefix, err)
		}

		lastChunk := roaring.New()
		if len(lastChunkBytes) > 0 {
			_, err = lastChunk.FromBuffer(lastChunkBytes)
			if err != nil {
				return fmt.Errorf("%s: couldn't read last log index chunk: %w, len(lastChunkBytes)=%d", logPrefix, err, len(lastChunkBytes))
			}
		}

		if _, err := currentBitmap.FromBuffer(v); err != nil {
			return err
		}
		currentBitmap.Or(lastChunk) // merge last existing chunk from db - next loop will overwrite it
		nextChunk := bitmapdb.ChunkIterator(currentBitmap, bitmapdb.ChunkLimit)
		for chunk := nextChunk(); chunk != nil; chunk = nextChunk() {
			buf.Reset()
			if _, err := chunk.WriteTo(buf); err != nil {
				return err
			}
			chunkKey := make([]byte, len(k)+4)
			copy(chunkKey, k)
			if currentBitmap.GetCardinality() == 0 {
				binary.BigEndian.PutUint32(chunkKey[len(k):], ^uint32(0))
				if err := next(k, chunkKey, common.CopyBytes(buf.Bytes())); err != nil {
					return err
				}
				break
			}
			binary.BigEndian.PutUint32(chunkKey[len(k):], chunk.Maximum())
			if err := next(k, chunkKey, common.CopyBytes(buf.Bytes())); err != nil {
				return err
			}
		}

		currentBitmap.Clear()
		return nil
	}

	if err := collectorUpdates.Load(logPrefix, db, changeset.Mapper[changesetBucket].IndexBucket, loaderFunc, etl.TransformArgs{Quit: quit}); err != nil {
		return err
	}

	return nil
}

func SpawnStorageHistoryIndex(s *StageState, db ethdb.Database, tmpdir string, quitCh <-chan struct{}) error {
	endBlock, err := s.ExecutionAt(db)
	logPrefix := s.state.LogPrefix()
	if err != nil {
		return fmt.Errorf("%s: getting last executed block: %w", logPrefix, err)
	}
	if endBlock == s.BlockNumber {
		s.Done()
		return nil
	}
	var blockNum uint64
	lastProcessedBlockNumber := s.BlockNumber
	if lastProcessedBlockNumber > 0 {
		blockNum = lastProcessedBlockNumber + 1
	}
	ig := core.NewIndexGenerator(logPrefix, db, quitCh)
	ig.TempDir = tmpdir
	if err := ig.GenerateIndex(blockNum, endBlock+1, dbutils.PlainStorageChangeSetBucket, tmpdir); err != nil {
		return fmt.Errorf("%s: fail to generate index: %w", logPrefix, err)
	}

	return s.DoneAndUpdate(db, endBlock)
}

func UnwindAccountHistoryIndex(u *UnwindState, s *StageState, db ethdb.Database, quitCh <-chan struct{}) error {
	logPrefix := s.state.LogPrefix()
	ig := core.NewIndexGenerator(logPrefix, db, quitCh)
	if err := ig.Truncate(u.UnwindPoint, dbutils.PlainAccountChangeSetBucket); err != nil {
		return fmt.Errorf("%s: fail to truncate index: %w", logPrefix, err)
	}
	if err := u.Done(db); err != nil {
		return fmt.Errorf("%s: %w", logPrefix, err)
	}
	return nil
}

func UnwindStorageHistoryIndex(u *UnwindState, s *StageState, db ethdb.Database, quitCh <-chan struct{}) error {
	logPrefix := s.state.LogPrefix()
	ig := core.NewIndexGenerator(logPrefix, db, quitCh)
	if err := ig.Truncate(u.UnwindPoint, dbutils.PlainStorageChangeSetBucket); err != nil {
		return fmt.Errorf("%s: fail to truncate index: %w", logPrefix, err)
	}
	if err := u.Done(db); err != nil {
		return fmt.Errorf("%s: %w", logPrefix, err)
	}
	return nil
}
