package consensus

import (
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"

	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/core/types"
)

type VerifyHeaderRequest struct {
	ID       uint64
	Header   []*types.Header
	Seal     []bool
	Deadline *time.Time
}

type VerifyHeaderResponse struct {
	ID   uint64
	Hash common.Hash
	Err  error
}

type HeadersRequest struct {
	ID                 uint64
	HighestHash        common.Hash
	HighestBlockNumber uint64
	Number             uint64
}

// ответ в виде пачки на HeadersRequest
type HeaderResponse struct {
	ID      uint64
	Headers []*types.Header
	BlockError
}

type BlockError struct {
	Hash   common.Hash
	Number uint64
	Err    error
}

type EngineProcess interface {
	HeaderVerification() chan<- VerifyHeaderRequest
	VerifyResults() <-chan VerifyHeaderResponse

	HeaderRequest() <-chan HeadersRequest
	HeaderResponse() chan<- HeaderResponse
}

type Process struct {
	Chain                 ChainHeaderReader
	VerifyHeaderRequests  chan VerifyHeaderRequest
	VerifyHeaderResponses chan VerifyHeaderResponse
	CleanupTicker         *time.Ticker
	HeadersRequests       chan HeadersRequest
	HeaderResponses       chan HeaderResponse

	VerifiedBlocks   *lru.Cache // common.Hash->*types.Header
	VerifiedBlocksMu sync.RWMutex

	ProcessingRequests   map[uint64]map[uint64]*VerifyRequest // reqID->blockNumber->VerifyRequest
	ProcessingRequestsMu sync.RWMutex
}

type VerifyRequest struct {
	ID              uint64
	Header          *types.Header
	Seal            bool
	Deadline        *time.Time
	KnownParents    []*types.Header
	ParentsExpected int
	From            uint64
	To              uint64
}

const (
	// fixme reduce numbers
	size        = 65536
	storageSize = 60000
	retry       = 100 * time.Millisecond
)

func NewProcess(chain ChainHeaderReader) *Process {
	verifiedBlocks, _ := lru.New(storageSize)
	return &Process{
		Chain:                 chain,
		VerifyHeaderRequests:  make(chan VerifyHeaderRequest, size),
		VerifyHeaderResponses: make(chan VerifyHeaderResponse, size),
		CleanupTicker:         time.NewTicker(retry),
		HeadersRequests:       make(chan HeadersRequest, size),
		HeaderResponses:       make(chan HeaderResponse, size),
		VerifiedBlocks:        verifiedBlocks,
		ProcessingRequests:    make(map[uint64]map[uint64]*VerifyRequest, size),
	}
}

func (p *Process) GetVerifyHeader() <-chan VerifyHeaderResponse {
	return p.VerifyHeaderResponses
}

func (p *Process) HeaderRequest() <-chan HeadersRequest {
	return p.HeadersRequests
}

func (p *Process) HeaderResponse() chan<- HeaderResponse {
	return p.HeaderResponses
}

func (p *Process) CacheHeader(header *types.Header) {
	p.VerifiedBlocksMu.Lock()
	defer p.VerifiedBlocksMu.Unlock()

	blockNum := header.Number.Uint64()
	blocksContainer, ok := p.VerifiedBlocks.Get(blockNum)
	var blocks []*types.Header
	if ok {
		blocks = blocksContainer.([]*types.Header)
	} else {
		blocks = append(blocks, header)
		p.VerifiedBlocks.Add(blockNum, blocks)
		return
	}

	for _, h := range blocks {
		if h.Hash() == header.Hash() {
			return
		}
	}

	blocks = append(blocks, header)

	p.VerifiedBlocks.Add(blockNum, blocks)
}

func (p *Process) GetCachedHeader(parentHash common.Hash, blockNum uint64) *types.Header {
	p.VerifiedBlocksMu.RLock()
	defer p.VerifiedBlocksMu.RUnlock()

	h, ok := p.VerifiedBlocks.Get(blockNum)
	if !ok {
		return nil
	}

	headers, ok := h.([]*types.Header)
	if !ok {
		return nil
	}

	for _, h := range headers {
		if h.Hash() == parentHash {
			return h
		}
	}

	return nil
}