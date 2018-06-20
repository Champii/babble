package net

import "github.com/champii/babble/hashgraph"

type SyncRequest struct {
	FromID string
	Known  map[string]int
}

type SyncResponse struct {
	FromID    string
	SyncLimit bool
	Events    []hashgraph.WireEvent
	Known     map[string]int
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

type EagerSyncRequest struct {
	FromID string
	Events []hashgraph.WireEvent
}

type EagerSyncResponse struct {
	FromID  string
	Success bool
}
