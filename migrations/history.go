package migrations

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/dbutils"
	"github.com/ledgerwatch/turbo-geth/common/etl"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/log"
)

var historyDup = Migration{
	Name: "history_bitmap_1",
	Up: func(db ethdb.Database, tmpdir string, progress []byte, CommitProgress etl.LoadCommitHandler) (err error) {
		logEvery := time.NewTicker(30 * time.Second)
		defer logEvery.Stop()
		logPrefix := "history_dup"

		const loadStep = "load"

		collectorB, err1 := etl.NewCollectorFromFiles(tmpdir + "1") // B - stands for blocks
		if err1 != nil {
			return err1
		}
		switch string(progress) {
		case "":
			// can't use files if progress field not set, clear them
			if collectorB != nil {
				collectorB.Close(logPrefix)
				collectorB = nil
			}

		case loadStep:
			if collectorB == nil {
				return ErrMigrationETLFilesDeleted
			}
			defer func() {
				// don't clean if error or panic happened
				if err != nil {
					return
				}
				if rec := recover(); rec != nil {
					panic(rec)
				}
				collectorB.Close(logPrefix)
			}()
			goto LoadStep
		}

		collectorB = etl.NewCriticalCollector(tmpdir+"1", etl.NewSortableBuffer(etl.BufferOptimalSize*4))
		defer func() {
			// don't clean if error or panic happened
			if err != nil {
				return
			}
			if rec := recover(); rec != nil {
				panic(rec)
			}
			collectorB.Close(logPrefix)
		}()

		if err = db.Walk(dbutils.AccountsHistoryBucket2, nil, 0, func(k, v []byte) (bool, error) {
			select {
			default:
			case <-logEvery.C:
				log.Info(fmt.Sprintf("[%s] Progress2", logPrefix), "key", fmt.Sprintf("%x", k))
			}
			index := dbutils.WrapHistoryIndex(v)

			blocks, exists, err := index.Decode()
			if err != nil {
				return false, err
			}
			for i, blockN := range blocks {
				newV := make([]byte, 9)
				binary.BigEndian.PutUint64(newV, blockN)
				if exists[i] {
					newV[8] = 1
				}
				//fmt.Printf("%x\n", k[:20])
				if err := collectorB.Collect(common.CopyBytes(
					k[:20]), newV); err != nil {
					return false, err
				}
			}
			return true, nil
		}); err != nil {
			return err
		}

		if err = db.(ethdb.BucketsMigrator).ClearBuckets(dbutils.AccountsHistoryBucket); err != nil {
			return fmt.Errorf("clearing the receipt bucket: %w", err)
		}

		// Commit clearing of the bucket - freelist should now be written to the database
		if err = CommitProgress(db, []byte(loadStep), false); err != nil {
			return fmt.Errorf("committing the removal of receipt table: %w", err)
		}

	LoadStep:
		// Now transaction would have been re-opened, and we should be re-using the space
		if err = collectorB.Load(logPrefix, db, dbutils.AccountsHistoryBucket, etl.IdentityLoadFunc, etl.TransformArgs{
			OnLoadCommit: CommitProgress,
		}); err != nil {
			return fmt.Errorf("loading the transformed data back into the bodies table: %w", err)
		}
		return nil
	},
}
