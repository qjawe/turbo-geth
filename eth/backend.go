// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package eth implements the Ethereum protocol.
package eth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	ethereum "github.com/ledgerwatch/turbo-geth"
	"github.com/ledgerwatch/turbo-geth/accounts"
	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/etl"
	"github.com/ledgerwatch/turbo-geth/common/hexutil"
	"github.com/ledgerwatch/turbo-geth/consensus"
	"github.com/ledgerwatch/turbo-geth/consensus/clique"
	"github.com/ledgerwatch/turbo-geth/consensus/ethash"
	"github.com/ledgerwatch/turbo-geth/consensus/process"
	"github.com/ledgerwatch/turbo-geth/core"
	"github.com/ledgerwatch/turbo-geth/core/bloombits"
	"github.com/ledgerwatch/turbo-geth/core/rawdb"
	"github.com/ledgerwatch/turbo-geth/core/types"
	"github.com/ledgerwatch/turbo-geth/core/vm"
	"github.com/ledgerwatch/turbo-geth/eth/downloader"
	"github.com/ledgerwatch/turbo-geth/eth/filters"
	"github.com/ledgerwatch/turbo-geth/eth/gasprice"
	"github.com/ledgerwatch/turbo-geth/eth/stagedsync"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/ethdb/remote/remotedbserver"
	"github.com/ledgerwatch/turbo-geth/event"
	"github.com/ledgerwatch/turbo-geth/internal/ethapi"
	"github.com/ledgerwatch/turbo-geth/log"
	"github.com/ledgerwatch/turbo-geth/miner"
	"github.com/ledgerwatch/turbo-geth/node"
	"github.com/ledgerwatch/turbo-geth/p2p"
	"github.com/ledgerwatch/turbo-geth/p2p/enode"
	"github.com/ledgerwatch/turbo-geth/p2p/enr"
	"github.com/ledgerwatch/turbo-geth/params"
	"github.com/ledgerwatch/turbo-geth/rlp"
	"github.com/ledgerwatch/turbo-geth/rpc"
	"github.com/ledgerwatch/turbo-geth/turbo/snapshotsync"
	"github.com/ledgerwatch/turbo-geth/turbo/snapshotsync/bittorrent"
)

// Ethereum implements the Ethereum full node service.
type Ethereum struct {
	config *Config

	// Handlers
	txPool          *core.TxPool
	blockchain      *core.BlockChain
	protocolManager *ProtocolManager
	dialCandidates  enode.Iterator

	// DB interfaces
	chainDb    *ethdb.ObjectDatabase // Block chain database
	chainKV    ethdb.KV              // Same as chainDb, but different interface
	privateAPI *grpc.Server

	eventMux       *event.TypeMux
	engine         *process.RemoteEngine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests

	APIBackend *EthAPIBackend

	miner     *miner.Miner
	gasPrice  *big.Int
	etherbase common.Address

	networkID     uint64
	netRPCService *ethapi.PublicNetAPI

	p2pServer     *p2p.Server
	txPoolStarted bool

	torrentClient *bittorrent.Client

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)
}

// New creates a new Ethereum object (including the
// initialisation of the common Ethereum object)
func New(stack *node.Node, config *Config) (*Ethereum, error) {
	// Ensure configuration values are compatible and sane
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.Ethereum in light sync mode, use les.LightEthereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Cmp(common.Big0) <= 0 {
		log.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", DefaultConfig.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(DefaultConfig.Miner.GasPrice)
	}
	if !config.Pruning && config.TrieDirtyCache > 0 {
		if config.SnapshotCache > 0 {
			config.TrieCleanCache += config.TrieDirtyCache * 3 / 5
			config.SnapshotCache += config.TrieDirtyCache * 2 / 5
		} else {
			config.TrieCleanCache += config.TrieDirtyCache
		}
		config.TrieDirtyCache = 0
	}

	tmpdir := path.Join(stack.Config().DataDir, etl.TmpDirName)

	// Assemble the Ethereum object
	var chainDb *ethdb.ObjectDatabase
	var err error
	if config.EnableDebugProtocol {
		if err = os.RemoveAll("simulator"); err != nil {
			return nil, fmt.Errorf("removing simulator db: %w", err)
		}
		chainDb = ethdb.MustOpen("simulator")
	} else {
		err = stack.ApplyMigrations("chaindata", tmpdir)
		if err != nil {
			return nil, fmt.Errorf("failed stack.ApplyMigrations: %w", err)
		}

		chainDb, err = stack.OpenDatabaseWithFreezer("chaindata", 0, 0, "", "")
		if err != nil {
			return nil, err
		}
	}

	chainConfig, genesisHash, _, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis, config.StorageMode.History, false /* overwrite */)

	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config", chainConfig)

	var torrentClient *bittorrent.Client
	if config.SyncMode == downloader.StagedSync && config.SnapshotMode != (snapshotsync.SnapshotMode{}) && config.NetworkID == params.MainnetChainConfig.ChainID.Uint64() {
		if config.ExternalSnapshotDownloaderAddr != "" {
			cli, cl, innerErr := snapshotsync.NewClient(config.ExternalSnapshotDownloaderAddr)
			if innerErr != nil {
				return nil, innerErr
			}
			defer cl() //nolint

			_, innerErr = cli.Download(context.Background(), &snapshotsync.DownloadSnapshotRequest{
				NetworkId: config.NetworkID,
				Type:      config.SnapshotMode.ToSnapshotTypes(),
			})
			if innerErr != nil {
				return nil, innerErr
			}

			waitDownload := func() (map[snapshotsync.SnapshotType]*snapshotsync.SnapshotsInfo, error) {
				snapshotReadinessCheck := func(mp map[snapshotsync.SnapshotType]*snapshotsync.SnapshotsInfo, tp snapshotsync.SnapshotType) bool {
					if mp[tp].Readiness != int32(100) {
						log.Info("Downloading", "snapshot", tp, "%", mp[tp].Readiness)
						return false
					}
					return true
				}
				for {
					mp := make(map[snapshotsync.SnapshotType]*snapshotsync.SnapshotsInfo)
					snapshots, err1 := cli.Snapshots(context.Background(), &snapshotsync.SnapshotsRequest{NetworkId: config.NetworkID})
					if err1 != nil {
						return nil, err1
					}
					for i := range snapshots.Info {
						if mp[snapshots.Info[i].Type].SnapshotBlock < snapshots.Info[i].SnapshotBlock && snapshots.Info[i] != nil {
							mp[snapshots.Info[i].Type] = snapshots.Info[i]
						}
					}

					downloaded := true
					if config.SnapshotMode.Headers {
						if !snapshotReadinessCheck(mp, snapshotsync.SnapshotType_headers) {
							downloaded = false
						}
					}
					if config.SnapshotMode.Bodies {
						if !snapshotReadinessCheck(mp, snapshotsync.SnapshotType_bodies) {
							downloaded = false
						}
					}
					if config.SnapshotMode.State {
						if !snapshotReadinessCheck(mp, snapshotsync.SnapshotType_state) {
							downloaded = false
						}
					}
					if config.SnapshotMode.Receipts {
						if !snapshotReadinessCheck(mp, snapshotsync.SnapshotType_receipts) {
							downloaded = false
						}
					}
					if downloaded {
						return mp, nil
					}
					time.Sleep(time.Second * 10)
				}
			}
			downloadedSnapshots, innerErr := waitDownload()
			if innerErr != nil {
				return nil, innerErr
			}
			snapshotKV := chainDb.KV()

			snapshotKV, innerErr = snapshotsync.WrapBySnapshotsFromDownloader(snapshotKV, downloadedSnapshots)
			if innerErr != nil {
				return nil, innerErr
			}
			chainDb.SetKV(snapshotKV)
			innerErr = snapshotsync.PostProcessing(chainDb, config.SnapshotMode, downloadedSnapshots)
			if innerErr != nil {
				return nil, innerErr
			}
		} else {
			var dbPath string
			dbPath, err = stack.Config().ResolvePath("snapshots")
			if err != nil {
				return nil, err
			}
			torrentClient, err = bittorrent.New(dbPath, config.SnapshotSeeding)
			if err != nil {
				return nil, err
			}

			err = torrentClient.Load(chainDb)
			if err != nil {
				return nil, err
			}
			err = torrentClient.AddSnapshotsTorrents(context.Background(), chainDb, config.NetworkID, config.SnapshotMode)
			if err == nil {
				torrentClient.Download()
				snapshotKV := chainDb.KV()
				mp, innerErr := torrentClient.GetSnapshots(chainDb, config.NetworkID)
				if innerErr != nil {
					return nil, innerErr
				}

				snapshotKV, innerErr = snapshotsync.WrapBySnapshotsFromDownloader(snapshotKV, mp)
				if innerErr != nil {
					return nil, innerErr
				}
				chainDb.SetKV(snapshotKV)
				innerErr = snapshotsync.PostProcessing(chainDb, config.SnapshotMode, mp)
				if innerErr != nil {
					return nil, innerErr
				}
			} else {
				log.Error("There was an error in snapshot init. Swithing to regular sync", "err", err)
			}
		}
	}

	eth := &Ethereum{
		config:         config,
		chainDb:        chainDb,
		chainKV:        chainDb.KV(),
		eventMux:       stack.EventMux(),
		accountManager: stack.AccountManager(),
		networkID:      config.NetworkID,
		gasPrice:       config.Miner.GasPrice,
		etherbase:      config.Miner.Etherbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		p2pServer:      stack.Server(),
		torrentClient:  torrentClient,
	}

	eth.engine = CreateConsensusEngine(stack, chainConfig, &config.Ethash, config.Miner.Notify, config.Miner.Noverify, chainDb)

	log.Info("Initialising Ethereum protocol", "versions", ProtocolVersions, "network", config.NetworkID)

	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}

	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, Geth %s only supports v%d", *bcVersion, params.VersionWithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			if err2 := rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion); err2 != nil {
				return nil, err2
			}
		}
	}

	err = ethdb.SetStorageModeIfNotExist(chainDb, config.StorageMode)
	if err != nil {
		return nil, err
	}

	sm, err := ethdb.GetStorageModeFromDB(chainDb)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(sm, config.StorageMode) {
		return nil, errors.New("mode is " + config.StorageMode.ToString() + " original mode is " + sm.ToString())
	}

	vmConfig, cacheConfig := BlockchainRuntimeConfig(config)
	txCacher := core.NewTxSenderCacher(runtime.NumCPU())
	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, chainConfig, eth.engine, vmConfig, eth.shouldPreserve, txCacher)
	if err != nil {
		return nil, err
	}
	if config.SyncMode != downloader.StagedSync {
		_, err = eth.blockchain.GetTrieDbState()
		if err != nil {
			return nil, err
		}
	}

	eth.blockchain.EnableReceipts(config.StorageMode.Receipts)
	eth.blockchain.EnableTxLookupIndex(config.StorageMode.TxIndex)

	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		eth.blockchain.SetHead(compat.RewindTo)
		err = rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
		if err != nil {
			return nil, err
		}
	}

	if config.TxPool.Journal != "" {
		config.TxPool.Journal, err = stack.ResolvePath(config.TxPool.Journal)
		if err != nil {
			return nil, err
		}
	}

	eth.txPool = core.NewTxPool(config.TxPool, chainConfig, chainDb, txCacher)

	stagedSync := config.StagedSync

	// setting notifier to support streaming events to rpc daemon
	remoteEvents := remotedbserver.NewEvents()
	if stagedSync == nil {
		// if there is not stagedsync, we create one with the custom notifier
		stagedSync = stagedsync.New(stagedsync.DefaultStages(), stagedsync.DefaultUnwindOrder(), stagedsync.OptionalParameters{Notifier: remoteEvents})
	} else {
		// otherwise we add one if needed
		if stagedSync.Notifier == nil {
			stagedSync.Notifier = remoteEvents
		}
	}

	if stack.Config().PrivateApiAddr != "" {
		if stack.Config().TLSConnection {
			// load peer cert/key, ca cert
			var creds credentials.TransportCredentials

			if stack.Config().TLSCACert != "" {
				var peerCert tls.Certificate
				var caCert []byte
				peerCert, err = tls.LoadX509KeyPair(stack.Config().TLSCertFile, stack.Config().TLSKeyFile)
				if err != nil {
					log.Error("load peer cert/key error:%v", err)
					return nil, err
				}
				caCert, err = ioutil.ReadFile(stack.Config().TLSCACert)
				if err != nil {
					log.Error("read ca cert file error:%v", err)
					return nil, err
				}
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				creds = credentials.NewTLS(&tls.Config{
					Certificates: []tls.Certificate{peerCert},
					ClientCAs:    caCertPool,
					ClientAuth:   tls.RequireAndVerifyClientCert,
				})
			} else {
				creds, err = credentials.NewServerTLSFromFile(stack.Config().TLSCertFile, stack.Config().TLSKeyFile)
			}

			if err != nil {
				return nil, err
			}
			eth.privateAPI, err = remotedbserver.StartGrpc(chainDb.KV(), eth, stack.Config().PrivateApiAddr, &creds, remoteEvents)
			if err != nil {
				return nil, err
			}
		} else {
			eth.privateAPI, err = remotedbserver.StartGrpc(chainDb.KV(), eth, stack.Config().PrivateApiAddr, nil, remoteEvents)
			if err != nil {
				return nil, err
			}
		}
	}

	checkpoint := config.Checkpoint
	if checkpoint == nil {
		//checkpoint = params.TrustedCheckpoints[genesisHash]
	}

	if eth.protocolManager, err = NewProtocolManager(chainConfig, checkpoint, config.SyncMode, config.NetworkID, eth.eventMux, eth.txPool, eth.engine, eth.blockchain, chainDb, config.Whitelist, stagedSync); err != nil {
		return nil, err
	}
	eth.miner = miner.New(eth, &config.Miner, chainConfig, eth.EventMux(), eth.engine, eth.isLocalBlock)
	eth.protocolManager.SetTmpDir(tmpdir)
	eth.protocolManager.SetBatchSize(int(config.CacheSize), int(config.BatchSize))

	if config.SyncMode != downloader.StagedSync {
		if err = eth.StartTxPool(); err != nil {
			return nil, err
		}
	}
	eth.APIBackend = &EthAPIBackend{stack.Config().ExtRPCEnabled(), eth, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.Miner.GasPrice
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, gpoParams)

	if config.SyncMode != downloader.StagedSync {
		eth.miner = miner.New(eth, &config.Miner, chainConfig, eth.EventMux(), eth.engine, eth.isLocalBlock)
		_ = eth.miner.SetExtra(makeExtraData(config.Miner.ExtraData))
	}

	if config.SyncMode != downloader.StagedSync {
		eth.APIBackend = &EthAPIBackend{stack.Config().ExtRPCEnabled(), eth, nil}
		gpoParams := config.GPO
		if gpoParams.Default == nil {
			gpoParams.Default = config.Miner.GasPrice
		}
		eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, gpoParams)
	}

	eth.dialCandidates, err = eth.setupDiscovery(&stack.Config().P2P)
	if err != nil {
		return nil, err
	}
	// Start the RPC service
	if config.SyncMode != downloader.StagedSync {
		id, err := eth.NetVersion()
		if err != nil {
			return nil, err
		}
		eth.netRPCService = ethapi.NewPublicNetAPI(eth.p2pServer, id)
	}

	// Register the backend on the node
	stack.RegisterAPIs(eth.APIs())
	stack.RegisterProtocols(eth.Protocols())
	stack.RegisterLifecycle(eth)
	return eth, nil
}

func BlockchainRuntimeConfig(config *Config) (vm.Config, *core.CacheConfig) {
	var (
		vmConfig = vm.Config{
			EnablePreimageRecording: config.EnablePreimageRecording,
			EWASMInterpreter:        config.EWASMInterpreter,
			EVMInterpreter:          config.EVMInterpreter,
			NoReceipts:              !config.StorageMode.Receipts,
		}
		cacheConfig = &core.CacheConfig{
			Pruning:             config.Pruning,
			BlocksBeforePruning: config.BlocksBeforePruning,
			BlocksToPrune:       config.BlocksToPrune,
			PruneTimeout:        config.PruningTimeout,
			TrieCleanLimit:      config.TrieCleanCache,
			TrieCleanNoPrefetch: config.NoPrefetch,
			TrieDirtyLimit:      config.TrieDirtyCache,
			TrieTimeLimit:       config.TrieTimeout,
			DownloadOnly:        config.DownloadOnly,
			NoHistory:           !config.StorageMode.History,
			ArchiveSyncInterval: uint64(config.ArchiveSyncInterval),
		}
	)
	return vmConfig, cacheConfig
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionMicro),
			"turbo-geth",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateConsensusEngine creates the required type of consensus engine instance for an Ethereum service
func CreateConsensusEngine(_ *node.Node, chainConfig *params.ChainConfig, config *ethash.Config, notify []string, noverify bool, db ethdb.Database) *process.RemoteEngine {
	var eng consensus.Engine
	// Otherwise assume proof-of-work
	switch config.PowMode {
	case ethash.ModeFake:
		log.Warn("Ethash used in fake mode")
		eng = ethash.NewFaker()
	case ethash.ModeTest:
		log.Warn("Ethash used in test mode")
		eng = ethash.NewTester(nil, noverify)
	case ethash.ModeShared:
		log.Warn("Ethash used in shared mode")
		eng = ethash.NewShared()
	default:
		if chainConfig.Clique != nil {
			eng = clique.NewCliqueVerifier(clique.New(chainConfig.Clique, db))
		} else {
			engine := ethash.New(ethash.Config{
				CachesInMem:      config.CachesInMem,
				CachesLockMmap:   config.CachesLockMmap,
				DatasetDir:       config.DatasetDir,
				DatasetsInMem:    config.DatasetsInMem,
				DatasetsOnDisk:   config.DatasetsOnDisk,
				DatasetsLockMmap: config.DatasetsLockMmap,
			}, notify, noverify)
			engine.SetThreads(-1) // Disable CPU mining
			eng = engine
		}
	}

	return process.NewRemoteEngine(eng, chainConfig)
}

// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Ethereum) APIs() []rpc.API {
	if s.APIBackend == nil {
		return []rpc.API{}
	}
	apis := ethapi.GetAPIs(s.APIBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		//{
		//	Namespace: "eth",
		//	Version:   "1.0",
		//	Service:   NewPublicEthereumAPI(s),
		//	Public:    true,
		//},
		//{
		//	Namespace: "eth",
		//	Version:   "1.0",
		//	Service:   NewPublicMinerAPI(s),
		//	Public:    true,
		//},
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		},
		//{
		//	Namespace: "miner",
		//	Version:   "1.0",
		//	Service:   NewPrivateMinerAPI(s),
		//	Public:    false,
		//},
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.APIBackend, false),
			Public:    true,
		},
		//{
		//	Namespace: "admin",
		//	Version:   "1.0",
		//	Service:   NewPrivateAdminAPI(s),
		//},
		//{
		//	Namespace: "debug",
		//	Version:   "1.0",
		//	Service:   NewPublicDebugAPI(s),
		//	Public:    true,
		//}, {
		//	Namespace: "debug",
		//	Version:   "1.0",
		//	Service:   NewPrivateDebugAPI(s),
		//},
		{
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *Ethereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Ethereum) Etherbase() (eb common.Address, err error) {
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()

	if etherbase != (common.Address{}) {
		return etherbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			etherbase := accounts[0].Address

			s.lock.Lock()
			s.etherbase = etherbase
			s.lock.Unlock()

			log.Info("Etherbase automatically configured", "address", etherbase)
			return etherbase, nil
		}
	}
	return common.Address{}, fmt.Errorf("etherbase must be explicitly specified")
}

// isLocalBlock checks whether the specified block is mined
// by local miner accounts.
//
// We regard two types of accounts as local miner account: etherbase
// and accounts specified via `txpool.locals` flag.
func (s *Ethereum) isLocalBlock(block *types.Block) bool {
	author, err := s.engine.Author(block.Header())
	if err != nil {
		log.Warn("Failed to retrieve block author", "number", block.NumberU64(), "hash", block.Hash(), "err", err)
		return false
	}
	// Check whether the given address is etherbase.
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()
	if author == etherbase {
		return true
	}
	// Check whether the given address is specified by `txpool.local`
	// CLI flag.
	for _, account := range s.config.TxPool.Locals {
		if account == author {
			return true
		}
	}
	return false
}

// shouldPreserve checks whether we should preserve the given block
// during the chain reorg depending on whether the author of block
// is a local account.
func (s *Ethereum) shouldPreserve(block *types.Block) bool {
	// The reason we need to disable the self-reorg preserving for clique
	// is it can be probable to introduce a deadlock.
	//
	// e.g. If there are 7 available signers
	//
	// r1   A
	// r2     B
	// r3       C
	// r4         D
	// r5   A      [X] F G
	// r6    [X]
	//
	// In the round5, the inturn signer E is offline, so the worst case
	// is A, F and G sign the block of round5 and reject the block of opponents
	// and in the round6, the last available signer B is offline, the whole
	// network is stuck.
	if _, ok := s.engine.Engine.(*clique.Clique); ok {
		return false
	}
	return s.isLocalBlock(block)
}

// SetEtherbase sets the mining reward address.
func (s *Ethereum) SetEtherbase(etherbase common.Address) {
	s.lock.Lock()
	s.etherbase = etherbase
	s.lock.Unlock()

	s.miner.SetEtherbase(etherbase)
}

// StartMining starts the miner with the given number of CPU threads. If mining
// is already running, this method adjust the number of threads allowed to use
// and updates the minimum price required by the transaction pool.
func (s *Ethereum) StartMining(threads int) error {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.Engine.(threaded); ok {
		log.Info("Updated mining threads", "threads", threads)
		if threads == 0 {
			threads = -1 // Disable the miner from within
		}
		th.SetThreads(threads)
	}
	// If the miner was not running, initialize it
	if !s.IsMining() {
		// Propagate the initial price point to the transaction pool
		s.lock.RLock()
		price := s.gasPrice
		s.lock.RUnlock()
		s.txPool.SetGasPrice(price)

		// Configure the local mining address
		eb, err := s.Etherbase()
		if err != nil {
			log.Error("Cannot start mining without etherbase", "err", err)
			return fmt.Errorf("etherbase missing: %v", err)
		}
		if clique, ok := s.engine.Engine.(*clique.Clique); ok {
			wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
			if wallet == nil || err != nil {
				log.Error("Etherbase account unavailable locally", "err", err)
				return fmt.Errorf("signer missing: %v", err)
			}
			clique.Authorize(eb, wallet.SignData)
		}
		// If mining is started, we can disable the transaction rejection mechanism
		// introduced to speed sync times.
		atomic.StoreUint32(&s.protocolManager.acceptTxs, 1)

		go s.miner.Start(eb)
	}
	return nil
}

// StopMining terminates the miner, both at the consensus engine level as well as
// at the block creation level.
func (s *Ethereum) StopMining() {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.Engine.(threaded); ok {
		th.SetThreads(-1)
	}
	// Stop the block creating itself
	s.miner.Stop()
}

func (s *Ethereum) IsMining() bool      { return s.miner.Mining() }
func (s *Ethereum) Miner() *miner.Miner { return s.miner }

func (s *Ethereum) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *Ethereum) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *Ethereum) TxPool() *core.TxPool               { return s.txPool }
func (s *Ethereum) EventMux() *event.TypeMux           { return s.eventMux }
func (s *Ethereum) Engine() consensus.Engine           { return s.engine }
func (s *Ethereum) ChainDb() ethdb.Database            { return s.chainDb }
func (s *Ethereum) ChainKV() ethdb.KV                  { return s.chainKV }
func (s *Ethereum) IsListening() bool                  { return true } // Always listening
func (s *Ethereum) EthVersion() int                    { return int(ProtocolVersions[0]) }
func (s *Ethereum) NetVersion() (uint64, error)        { return s.networkID, nil }
func (s *Ethereum) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
func (s *Ethereum) SyncProgress() ethereum.SyncProgress {
	return s.protocolManager.downloader.Progress()
}
func (s *Ethereum) Synced() bool      { return atomic.LoadUint32(&s.protocolManager.acceptTxs) == 1 }
func (s *Ethereum) ArchiveMode() bool { return !s.config.Pruning }

// Protocols returns all the currently configured
// network protocols to start.
func (s *Ethereum) Protocols() []p2p.Protocol {
	protos := make([]p2p.Protocol, len(ProtocolVersions))
	for i, vsn := range ProtocolVersions {
		protos[i] = s.protocolManager.makeProtocol(vsn)
		protos[i].Attributes = []enr.Entry{s.currentEthEntry()}
		protos[i].DialCandidates = s.dialCandidates
	}

	if s.config.EnableDebugProtocol {
		// Debug
		protos = append(protos, s.protocolManager.makeDebugProtocol())
	}

	return protos
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *Ethereum) Start() error {
	s.startEthEntryUpdate(s.p2pServer.LocalNode())

	// Figure out a max peers count based on the server limits
	maxPeers := s.p2pServer.MaxPeers
	withTxPool := s.config.SyncMode != downloader.StagedSync
	// Start the networking layer and the light server if requested
	return s.protocolManager.Start(maxPeers, withTxPool)
}

func (s *Ethereum) StartTxPool() error {
	if s.txPoolStarted {
		return errors.New("transaction pool is already started")
	}
	headHash := rawdb.ReadHeadHeaderHash(s.chainDb)
	headNumber := rawdb.ReadHeaderNumber(s.chainDb, headHash)
	head := rawdb.ReadHeader(s.chainDb, headHash, *headNumber)
	if err := s.txPool.Start(head.GasLimit, *headNumber); err != nil {
		return err
	}
	if err := s.protocolManager.StartTxPool(); err != nil {
		s.txPool.Stop()
		return err
	}

	s.txPoolStarted = true
	return nil
}

func (s *Ethereum) StopTxPool() error {
	if !s.txPoolStarted {
		return errors.New("transaction pool is already stopped")
	}
	s.protocolManager.StopTxPool()
	s.txPool.Stop()

	s.txPoolStarted = false
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *Ethereum) Stop() error {
	// Stop all the peer-related stuff first.
	s.protocolManager.Stop()
	if s.privateAPI != nil {
		shutdownDone := make(chan bool)
		go func() {
			defer close(shutdownDone)
			s.privateAPI.GracefulStop()
		}()
		select {
		case <-time.After(1 * time.Second): // shutdown deadline
			s.privateAPI.Stop()
		case <-shutdownDone:
		}
	}

	// Then stop everything else.
	if err := s.StopTxPool(); err != nil {
		log.Warn("error while stopping transaction pool", "err", err)
	}
	s.miner.Stop()
	s.blockchain.Stop()
	s.engine.Close()
	s.eventMux.Stop()
	if s.txPool != nil {
		s.txPool.Stop()
	}
	return nil
}
