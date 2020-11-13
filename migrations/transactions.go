package migrations

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/ledgerwatch/turbo-geth/common/dbutils"
	"github.com/ledgerwatch/turbo-geth/common/etl"
	"github.com/ledgerwatch/turbo-geth/core/rawdb"
	"github.com/ledgerwatch/turbo-geth/core/types"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/log"
	"github.com/ledgerwatch/turbo-geth/rlp"
)

var transactionsTable = Migration{
	Name: "tx_table_1",
	Up: func(db ethdb.Database, tmpdir string, progress []byte, CommitProgress etl.LoadCommitHandler) (err error) {
		logEvery := time.NewTicker(30 * time.Second)
		defer logEvery.Stop()
		logPrefix := "tx_table"

		const loadStep = "load"
		reader := bytes.NewReader(nil)

		collectorR, err1 := etl.NewCollectorFromFiles(tmpdir + "1")
		if err1 != nil {
			return err1
		}
		collectorL, err1 := etl.NewCollectorFromFiles(tmpdir + "2")
		if err1 != nil {
			return err1
		}
		switch string(progress) {
		case "":
			// can't use files if progress field not set, clear them
			if collectorR != nil {
				collectorR.Close(logPrefix)
				collectorR = nil
			}

			if collectorL != nil {
				collectorL.Close(logPrefix)
				collectorL = nil
			}
		case loadStep:
			if collectorR == nil || collectorL == nil {
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
				collectorR.Close(logPrefix)
				collectorL.Close(logPrefix)
			}()
			goto LoadStep
		}

		collectorR = etl.NewCriticalCollector(tmpdir+"1", etl.NewSortableBuffer(etl.BufferOptimalSize*4))
		collectorL = etl.NewCriticalCollector(tmpdir+"2", etl.NewSortableBuffer(etl.BufferOptimalSize*4))
		defer func() {
			// don't clean if error or panic happened
			if err != nil {
				return
			}
			if rec := recover(); rec != nil {
				panic(rec)
			}
			collectorR.Close(logPrefix)
			collectorL.Close(logPrefix)
		}()

		if err = db.Walk(dbutils.BlockBodyPrefix, nil, 0, func(k, v []byte) (bool, error) {
			blockNum := binary.BigEndian.Uint64(k[:8])
			select {
			default:
			case <-logEvery.C:
				log.Info(fmt.Sprintf("[%s] Progress2", logPrefix), "blockNum", blockNum)
			}

			hash, err := rawdb.ReadCanonicalHash(db, blockNum)
			if err != nil {
				return false, err
			}
			if !bytes.Equal(hash.Bytes(), k[8:]) {

			}

			body := new(types.Body)
			reader.Reset(v)
			if err := rlp.Decode(reader, body); err != nil {
				return false, fmt.Errorf("%s: invalid block body RLP: %w", logPrefix, err)
			}

			ids := make([]uint64, len(body.Transactions))
			for i, txn := range body.Transactions {
				newK := make([]byte, 8)
				// TODO: get sequence
				txId := uint64(1)
				ids[i] = txId

				txnBytes, err := rlp.EncodeToBytes(txn)
				if err != nil {
					return false, err
				}

				binary.BigEndian.PutUint64(newK, txId)
				err = collectorR.Collect(newK, txnBytes)
				if err != nil {
					return false, err
				}
			}

			body.Transactions = nil
			body.TxIds = ids

			return true, nil
		}); err != nil {
			return err
		}

		if err = db.(ethdb.BucketsMigrator).ClearBuckets(dbutils.EthTx); err != nil {
			return fmt.Errorf("clearing the receipt bucket: %w", err)
		}

		// Commit clearing of the bucket - freelist should now be written to the database
		if err = CommitProgress(db, []byte(loadStep), false); err != nil {
			return fmt.Errorf("committing the removal of receipt table: %w", err)
		}

	LoadStep:
		// Commit again
		if err = CommitProgress(db, []byte(loadStep), false); err != nil {
			return fmt.Errorf("committing the removal of receipt table: %w", err)
		}
		// Now transaction would have been re-opened, and we should be re-using the space
		if err = collectorR.Load(logPrefix, db, dbutils.EthTx, etl.IdentityLoadFunc, etl.TransformArgs{
			OnLoadCommit: CommitProgress,
		}); err != nil {
			return fmt.Errorf("loading the transformed data back into the receipts table: %w", err)
		}
		return nil
	},
}
