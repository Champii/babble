package node

import (
	"math/rand"

	"github.com/champii/babble/net"
)

type PeerSelector interface {
	Peers() []net.Peer
	UpdateLast(peer string)
	AddPeer(peer net.Peer)
	Next() net.Peer
}

//+++++++++++++++++++++++++++++++++++++++
//RANDOM

type RandomPeerSelector struct {
	peers []net.Peer
	last  string
}

func NewRandomPeerSelector(participants []net.Peer, localAddr string) *RandomPeerSelector {
	_, peers := net.ExcludePeer(participants, localAddr)
	return &RandomPeerSelector{
		peers: peers,
	}
}

func (ps *RandomPeerSelector) Peers() []net.Peer {
	return ps.peers
}

func (ps *RandomPeerSelector) AddPeer(peer net.Peer) {
	ps.peers = append(ps.peers, peer)
}

func (ps *RandomPeerSelector) UpdateLast(peer string) {
	ps.last = peer
}

func (ps *RandomPeerSelector) Next() net.Peer {
	selectablePeers := ps.peers
	if len(selectablePeers) > 1 {
		_, selectablePeers = net.ExcludePeer(selectablePeers, ps.last)
	}

	i := rand.Intn(len(selectablePeers))
	peer := selectablePeers[i]
	return peer
}
