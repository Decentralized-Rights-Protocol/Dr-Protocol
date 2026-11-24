package store

import (
	"fmt"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/consensus"
	"crypto/ed25519"
)

// ValidateChain checks contiguous heights, parent links and every persisted
// quorum certificate. Call before restoring the tip into the live engine.
func (s *ChainStore) ValidateChain(validators map[string]ed25519.PublicKey) error {
	blocks, err := s.Blocks()
	if err != nil { return err }
	var previous *consensus.Block
	for i := range blocks {
		block := blocks[i]
		expectedHeight := uint64(i+1)
		if block.Height != expectedHeight { return fmt.Errorf("chain validation: expected height %d, got %d",expectedHeight,block.Height) }
		expectedParent := ""
		if previous != nil { expectedParent = previous.Hash() }
		if block.PreviousHash != expectedParent { return fmt.Errorf("chain validation: invalid parent at height %d",block.Height) }
		cert, ok, err := s.Certificate(block.Height)
		if err != nil { return err }
		if !ok { return fmt.Errorf("chain validation: missing certificate at height %d",block.Height) }
		if err := consensus.VerifyCertificate(block,cert,validators); err != nil { return fmt.Errorf("chain validation: invalid certificate at height %d: %w",block.Height,err) }
		copy := block
		previous = &copy
	}
	tip, exists, err := s.Tip()
	if err != nil { return err }
	if exists && (len(blocks)==0 || blocks[len(blocks)-1].Hash()!=tip.Hash()) { return fmt.Errorf("chain validation: tip index does not match blocks") }
	if !exists && len(blocks)>0 { return fmt.Errorf("chain validation: blocks exist but tip index is missing") }
	return nil
}
