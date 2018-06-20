package babble

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"time"

	"github.com/champii/babble/hashgraph"
	"github.com/sirupsen/logrus"
)

type StateHash struct {
	Hash []byte
}

// CommitResponse captures both a response and a potential error.
type CommitResponse struct {
	StateHash []byte
	Error     error
}

// Commit provides a response mechanism.
type Commit struct {
	Block    hashgraph.Block
	RespChan chan<- CommitResponse
}

type Validate struct {
	Tx       []byte
	RespChan chan<- bool
}

// Respond is used to respond with a response, error or both
func (r *Commit) Respond(stateHash []byte, err error) {
	r.RespChan <- CommitResponse{stateHash, err}
}

type SocketBabbleProxyServer struct {
	netListener *net.Listener
	rpcServer   *rpc.Server
	commitCh    chan Commit
	validateCh  chan Validate
	timeout     time.Duration
	logger      *logrus.Logger
}

func NewSocketBabbleProxyServer(bindAddress string,
	timeout time.Duration,
	logger *logrus.Logger) (*SocketBabbleProxyServer, error) {

	server := &SocketBabbleProxyServer{
		commitCh:   make(chan Commit),
		validateCh: make(chan Validate),
		timeout:    timeout,
		logger:     logger,
	}

	if err := server.register(bindAddress); err != nil {
		return nil, err
	}

	return server, nil
}

func (p *SocketBabbleProxyServer) register(bindAddress string) error {
	rpcServer := rpc.NewServer()
	rpcServer.RegisterName("State", p)
	p.rpcServer = rpcServer

	l, err := net.Listen("tcp", bindAddress)
	if err != nil {
		return err
	}

	p.netListener = &l

	return nil
}

func (p *SocketBabbleProxyServer) listen() error {
	for {
		conn, err := (*p.netListener).Accept()
		if err != nil {
			return err
		}

		go (*p.rpcServer).ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

func (p *SocketBabbleProxyServer) CommitBlock(block hashgraph.Block, stateHash *StateHash) (err error) {
	// Send the Commit over
	respCh := make(chan CommitResponse)
	p.commitCh <- Commit{
		Block:    block,
		RespChan: respCh,
	}

	// Wait for a response
	select {
	case commitResp := <-respCh:
		stateHash.Hash = commitResp.StateHash
		if commitResp.Error != nil {
			err = commitResp.Error
		}
	case <-time.After(p.timeout):
		err = fmt.Errorf("command timed out")
	}

	p.logger.WithFields(logrus.Fields{
		"block":      block.Index(),
		"state_hash": stateHash.Hash,
		"err":        err,
	}).Debug("BabbleProxyServer.CommitBlock")

	return

}

func (p *SocketBabbleProxyServer) ValidateTx(tx []byte, res *bool) (err error) {
	// Send the Commit over
	respCh := make(chan bool)
	p.validateCh <- Validate{
		Tx:       tx,
		RespChan: respCh,
	}

	// Wait for a response
	select {
	case commitResp := <-respCh:
		*res = commitResp
	case <-time.After(p.timeout):
		err = fmt.Errorf("command timed out")
	}

	p.logger.WithFields(logrus.Fields{
		"err": err,
	}).Debug("BabbleProxyServer.ValidateTx")

	return

}
