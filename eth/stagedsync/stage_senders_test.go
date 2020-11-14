package stagedsync

import (
	"context"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/core/rawdb"
	"github.com/ledgerwatch/turbo-geth/core/types"
	"github.com/ledgerwatch/turbo-geth/eth/stagedsync/stages"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSenders(t *testing.T) {
	db, ctx, require := ethdb.NewMemDatabase(), context.Background(), require.New(t)

	//func NewTransaction(nonce uint64, to common.Address, amount *uint256.Int, gasLimit uint64, gasPrice *uint256.Int, data []byte) *Transaction {
	// prepare db so it works with our test
	rawdb.WriteBodyFromNetwork(ctx, db, common.HexToHash("01"), 1, &types.Body{
		Transactions: []*types.Transaction{
			types.NewTransaction(1, common.HexToAddress("01"), uint256.NewInt(), 1, uint256.NewInt(), nil),
			types.NewTransaction(2, common.HexToAddress("02"), uint256.NewInt(), 2, uint256.NewInt(), nil),
		},
	})
	require.NoError(rawdb.WriteCanonicalHash(db, common.HexToHash("01"), 1))
	rawdb.WriteBodyFromNetwork(ctx, db, common.HexToHash("02"), 2, &types.Body{
		Transactions: []*types.Transaction{
			types.NewTransaction(3, common.HexToAddress("03"), uint256.NewInt(), 3, uint256.NewInt(), nil),
			types.NewTransaction(4, common.HexToAddress("04"), uint256.NewInt(), 4, uint256.NewInt(), nil),
			types.NewTransaction(5, common.HexToAddress("05"), uint256.NewInt(), 5, uint256.NewInt(), nil),
		},
	})
	require.NoError(rawdb.WriteCanonicalHash(db, common.HexToHash("02"), 2))
	require.NoError(stages.SaveStageProgress(db, stages.Bodies, 2, nil))

	cfg := Stage3Config{
		BatchSize:       1024,
		BlockSize:       1024,
		BufferSize:      (1024 * 10 / 20) * 10000, // 20*4096
		NumOfGoroutines: 2,
		ReadChLen:       4,
		Now:             time.Now(),
	}
	err := SpawnRecoverSendersStage(cfg, &StageState{Stage: stages.Senders}, db, params.MainnetChainConfig, 2, "", nil)
	assert.NoError(t, err)

	found := rawdb.ReadBody(db, common.HexToHash("01"), 1)
	assert.NotNil(t, found)
	found = rawdb.ReadBody(db, common.HexToHash("02"), 2)
	assert.NotNil(t, found)

}
