// Package store provides durable blockchain state storage backed by LevelDB.
// It is intentionally separate from the in-memory MVP request/proof Store.
package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/consensus"
)

var (
	ErrChainHeight = errors.New("store: block height does not extend committed chain")
	ErrChainParent = errors.New("store: block parent does not match committed tip")
)

type ChainStore struct { db *leveldb.DB }

func OpenChain(path string) (*ChainStore, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil { return nil, fmt.Errorf("open DRP chain database: %w", err) }
	return &ChainStore{db:db}, nil
}

func (s *ChainStore) Close() error { return s.db.Close() }

func (s *ChainStore) Tip() (consensus.Block, bool, error) {
	raw, err := s.db.Get([]byte("chain:tip"), nil)
	if err == leveldb.ErrNotFound { return consensus.Block{}, false, nil }
	if err != nil { return consensus.Block{}, false, err }
	height, err := strconv.ParseUint(string(raw),10,64)
	if err != nil { return consensus.Block{}, false, fmt.Errorf("decode chain tip: %w",err) }
	block, ok, err := s.Block(height)
	return block, ok, err
}

func (s *ChainStore) Block(height uint64) (consensus.Block, bool, error) {
	raw, err := s.db.Get(blockKey(height), nil)
	if err == leveldb.ErrNotFound { return consensus.Block{}, false, nil }
	if err != nil { return consensus.Block{}, false, err }
	var block consensus.Block
	if err := json.Unmarshal(raw,&block); err != nil { return consensus.Block{}, false, fmt.Errorf("decode block %d: %w",height,err) }
	return block, true, nil
}

// CommitBlock atomically stores a block, its quorum certificate and the new tip.
// It validates the chain extension against durable state before writing.
func (s *ChainStore) CommitBlock(block consensus.Block, cert consensus.Certificate, validators map[string]ed25519.PublicKey) error {
	if err := consensus.VerifyCertificate(block,cert,validators); err != nil { return fmt.Errorf("invalid commit certificate: %w",err) }
	tip, exists, err := s.Tip()
	if err != nil { return err }
	expectedHeight, expectedParent := uint64(1), ""
	if exists { expectedHeight, expectedParent = tip.Height+1, tip.Hash() }
	if block.Height != expectedHeight { return ErrChainHeight }
	if block.PreviousHash != expectedParent { return ErrChainParent }
	blockBytes, err := json.Marshal(block)
	if err != nil { return err }
	certBytes, err := json.Marshal(cert)
	if err != nil { return err }
	batch := new(leveldb.Batch)
	batch.Put(blockKey(block.Height),blockBytes)
	batch.Put(certificateKey(block.Height),certBytes)
	batch.Put([]byte("chain:tip"),[]byte(strconv.FormatUint(block.Height,10)))
	return s.db.Write(batch,nil)
}

func (s *ChainStore) Certificate(height uint64) (consensus.Certificate, bool, error) {
	raw, err := s.db.Get(certificateKey(height),nil)
	if err == leveldb.ErrNotFound { return consensus.Certificate{}, false, nil }
	if err != nil { return consensus.Certificate{}, false, err }
	var cert consensus.Certificate
	if err := json.Unmarshal(raw,&cert); err != nil { return consensus.Certificate{}, false, fmt.Errorf("decode certificate %d: %w",height,err) }
	return cert,true,nil
}

func (s *ChainStore) Blocks() ([]consensus.Block,error) {
	iter := s.db.NewIterator(util.BytesPrefix([]byte("block:")),nil)
	defer iter.Release()
	blocks := make([]consensus.Block,0)
	for iter.Next() {
		var block consensus.Block
		if err := json.Unmarshal(iter.Value(),&block); err != nil { return nil,err }
		blocks = append(blocks,block)
	}
	if err := iter.Error(); err != nil { return nil,err }
	return blocks,nil
}

func blockKey(height uint64) []byte { return []byte(fmt.Sprintf("block:%020d",height)) }
func certificateKey(height uint64) []byte { return []byte(fmt.Sprintf("certificate:%020d",height)) }
