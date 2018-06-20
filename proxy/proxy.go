package proxy

import (
	"github.com/champii/babble/hashgraph"
	"github.com/champii/babble/proxy/babble"
)

type AppProxy interface {
	SubmitCh() chan []byte
	CommitBlock(block hashgraph.Block) ([]byte, error)
	ValidateTx(tx []byte) (bool, error)
}

type BabbleProxy interface {
	ValidateCh() chan babble.Validate
	CommitCh() chan babble.Commit
	SubmitTx(tx []byte) error
}
