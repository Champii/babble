package node

import (
	"crypto/ecdsa"
	"fmt"
	"strconv"
	"testing"

	"github.com/champii/babble/common"
	"github.com/champii/babble/crypto"
	hg "github.com/champii/babble/hashgraph"
)

func TestInit(t *testing.T) {
	key, _ := crypto.GenerateECDSAKey()
	participants := map[string]string{
		fmt.Sprintf("0x%X", crypto.FromECDSAPub(&key.PublicKey)): "0",
	}
	core := NewCore("0", key, participants, hg.NewInmemStore(participants, 10), nil, common.NewTestLogger(t))
	if err := core.Init(); err != nil {
		t.Fatalf("Init returned and error: %s", err)
	}
}

func initCores(n int, t *testing.T) (map[string]Core, map[string]*ecdsa.PrivateKey, map[string]string) {
	cacheSize := 1000

	cores := make(map[string]Core)
	index := make(map[string]string)

	participantKeys := map[string]*ecdsa.PrivateKey{}
	participants := make(map[string]string)
	for i := 0; i < n; i++ {
		key, _ := crypto.GenerateECDSAKey()
		participantKeys[string(crypto.FromECDSAPub(&key.PublicKey))] = key
		participants[fmt.Sprintf("0x%X", crypto.FromECDSAPub(&key.PublicKey))] = string(crypto.FromECDSAPub(&key.PublicKey))
	}

	for hash, key := range participants {
		core := NewCore(hash, participantKeys[hash], participants,
			hg.NewInmemStore(participants, cacheSize), nil, common.NewTestLogger(t))
		core.Init()
		cores[hash] = core
		index[fmt.Sprintf("e%d", hash)] = core.Head
	}

	return cores, participantKeys, index
}

/*
|  e12  |
|   | \ |
|   |   e20
|   | / |
|   /   |
| / |   |
e01 |   |
| \ |   |
e0  e1  e2
0   1   2
*/
func initHashgraph(cores map[string]Core, keys map[string]*ecdsa.PrivateKey, index map[string]string, participant string) {
	for k, c := range cores {
		if k != participant {

			event, _ := c.GetEvent(index[fmt.Sprintf("e%d", k)])
			pc := cores[participant]
			if err := pc.InsertEvent(event, true); err != nil {
				fmt.Printf("error inserting %s: %s\n", getName(index, event.Hex()), err)
			}
		}
	}

	c0 := cores["0"]
	c1 := cores["1"]
	c2 := cores["2"]

	event01 := hg.NewEvent([][]byte{}, nil,
		[]string{index["e0"], index["e1"]}, //e0 and e1
		c0.PubKey(), 1)

	if err := insertEvent(cores, keys, index, event01, "e01", participant, "0"); err != nil {
		fmt.Printf("error inserting e01: %s\n", err)
	}

	event20 := hg.NewEvent([][]byte{}, nil,
		[]string{index["e2"], index["e01"]}, //e2 and e01
		c2.PubKey(), 1)
	if err := insertEvent(cores, keys, index, event20, "e20", participant, "2"); err != nil {
		fmt.Printf("error inserting e20: %s\n", err)
	}

	event12 := hg.NewEvent([][]byte{}, nil,
		[]string{index["e1"], index["e20"]}, //e1 and e20
		c1.PubKey(), 1)
	if err := insertEvent(cores, keys, index, event12, "e12", participant, "1"); err != nil {
		fmt.Printf("error inserting e12: %s\n", err)
	}
}

func insertEvent(cores map[string]Core, keys map[string]*ecdsa.PrivateKey, index map[string]string,
	event hg.Event, name string, particant string, creator string) error {

	c := cores[particant]

	if particant == creator {
		if err := c.SignAndInsertSelfEvent(event); err != nil {
			return err
		}
		//event is not signed because passed by value
		index[name] = c.Head
	} else {
		event.Sign(keys[creator])
		if err := c.InsertEvent(event, true); err != nil {
			return err
		}
		index[name] = event.Hex()
	}
	return nil
}

func TestEventDiff(t *testing.T) {
	cores, keys, index := initCores(3, t)

	initHashgraph(cores, keys, index, "0")

	/*
	   P0 knows

	   |  e12  |
	   |   | \ |
	   |   |   e20
	   |   | / |
	   |   /   |
	   | / |   |
	   e01 |   |        P1 knows
	   | \ |   |
	   e0  e1  e2       |   e1  |
	   0   1   2        0   1   2
	*/

	c1 := cores["1"]
	knownBy1 := c1.KnownEvents()

	c0 := cores["0"]

	unknownBy1, err := c0.EventDiff(knownBy1)
	if err != nil {
		t.Fatal(err)
	}

	if l := len(unknownBy1); l != 5 {
		t.Fatalf("length of unknown should be 5, not %d", l)
	}

	expectedOrder := []string{"e0", "e2", "e01", "e20", "e12"}
	for i, e := range unknownBy1 {
		if name := getName(index, e.Hex()); name != expectedOrder[i] {
			t.Fatalf("element %d should be %s, not %s", i, expectedOrder[i], name)
		}
	}

}

func TestSync(t *testing.T) {
	cores, _, index := initCores(3, t)

	/*
	   core 0           core 1          core 2

	   e0  |   |        |   e1  |       |   |   e2
	   0   1   2        0   1   2       0   1   2
	*/

	//core 1 is going to tell core 0 everything it knows
	if err := synchronizeCores(cores, "1", "0", [][]byte{}); err != nil {
		t.Fatal(err)
	}

	/*
	   core 0           core 1          core 2

	   e01 |   |
	   | \ |   |
	   e0  e1  |        |   e1  |       |   |   e2
	   0   1   2        0   1   2       0   1   2
	*/

	c0 := cores["0"]
	c1 := cores["1"]
	c2 := cores["2"]
	knownBy0 := c0.KnownEvents()
	if k := knownBy0[c0.ID()]; k != 1 {
		t.Fatalf("core 0 should have last-index 1 for core 0, not %d", k)
	}
	if k := knownBy0[c1.ID()]; k != 0 {
		t.Fatalf("core 0 should have last-index 0 for core 1, not %d", k)
	}
	if k := knownBy0[c2.ID()]; k != -1 {
		t.Fatalf("core 0 should have last-index -1 for core 2, not %d", k)
	}
	core0Head, _ := c0.GetHead()
	if core0Head.SelfParent() != index["e0"] {
		t.Fatalf("core 0 head self-parent should be e0")
	}
	if core0Head.OtherParent() != index["e1"] {
		t.Fatalf("core 0 head other-parent should be e1")
	}
	index["e01"] = core0Head.Hex()

	//core 0 is going to tell core 2 everything it knows
	if err := synchronizeCores(cores, "0", "2", [][]byte{}); err != nil {
		t.Fatal(err)
	}

	/*

	   core 0           core 1          core 2

	                                    |   |  e20
	                                    |   | / |
	                                    |   /   |
	                                    | / |   |
	   e01 |   |                        e01 |   |
	   | \ |   |                        | \ |   |
	   e0  e1  |        |   e1  |       e0  e1  e2
	   0   1   2        0   1   2       0   1   2
	*/

	knownBy2 := c2.KnownEvents()
	if k := knownBy2[c0.ID()]; k != 1 {
		t.Fatalf("core 2 should have last-index 1 for core 0, not %d", k)
	}
	if k := knownBy2[c1.ID()]; k != 0 {
		t.Fatalf("core 2 should have last-index 0 core 1, not %d", k)
	}
	if k := knownBy2[c2.ID()]; k != 1 {
		t.Fatalf("core 2 should have last-index 1 for core 2, not %d", k)
	}
	core2Head, _ := c2.GetHead()
	if core2Head.SelfParent() != index["e2"] {
		t.Fatalf("core 2 head self-parent should be e2")
	}
	if core2Head.OtherParent() != index["e01"] {
		t.Fatalf("core 2 head other-parent should be e01")
	}
	index["e20"] = core2Head.Hex()

	//core 2 is going to tell core 1 everything it knows
	if err := synchronizeCores(cores, "2", "1", [][]byte{}); err != nil {
		t.Fatal(err)
	}

	/*

	   core 0           core 1          core 2

	                    |  e12  |
	                    |   | \ |
	                    |   |  e20      |   |  e20
	                    |   | / |       |   | / |
	                    |   /   |       |   /   |
	                    | / |   |       | / |   |
	   e01 |   |        e01 |   |       e01 |   |
	   | \ |   |        | \ |   |       | \ |   |
	   e0  e1  |        e0  e1  e2      e0  e1  e2
	   0   1   2        0   1   2       0   1   2
	*/

	knownBy1 := c1.KnownEvents()
	if k := knownBy1[c0.ID()]; k != 1 {
		t.Fatalf("core 1 should have last-index 1 for core 0, not %d", k)
	}
	if k := knownBy1[c1.ID()]; k != 1 {
		t.Fatalf("core 1 should have last-index 1 for core 1, not %d", k)
	}
	if k := knownBy1[c2.ID()]; k != 1 {
		t.Fatalf("core 1 should have last-index 1 for core 2, not %d", k)
	}
	core1Head, _ := c1.GetHead()
	if core1Head.SelfParent() != index["e1"] {
		t.Fatalf("core 1 head self-parent should be e1")
	}
	if core1Head.OtherParent() != index["e20"] {
		t.Fatalf("core 1 head other-parent should be e20")
	}
	index["e12"] = core1Head.Hex()

}

/*
h0  |   h2
| \ | / |
|   h1  |
|  /|   |--------------------
g02 |   | R2
| \ |   |
|   \   |
|   | \ |
|   |  g21
|   | / |
|  g10  |
| / |   |
g0  |   g2
| \ | / |
|   g1  |
|  /|   |--------------------
f02 |   | R1
| \ |   |
|   \   |
|   | \ |
|   |  f21
|   | / |
|  f10  |
| / |   |
f0  |   f2
| \ | / |
|   f1  |
|  /|   |--------------------
e02 |   | R0 Consensus
| \ |   |
|   \   |
|   | \ |
|   |  e21
|   | / |
|  e10  |
| / |   |
e0  e1  e2
0   1    2
*/
type play struct {
	from    string
	to      string
	payload [][]byte
}

func initConsensusHashgraph(t *testing.T) map[string]Core {
	cores, _, _ := initCores(3, t)
	playbook := []play{
		play{from: "0", to: "1", payload: [][]byte{[]byte("e10")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("e21")}},
		play{from: "2", to: "0", payload: [][]byte{[]byte("e02")}},
		play{from: "0", to: "1", payload: [][]byte{[]byte("f1")}},
		play{from: "1", to: "0", payload: [][]byte{[]byte("f0")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("f2")}},

		play{from: "0", to: "1", payload: [][]byte{[]byte("f10")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("f21")}},
		play{from: "2", to: "0", payload: [][]byte{[]byte("f02")}},
		play{from: "0", to: "1", payload: [][]byte{[]byte("g1")}},
		play{from: "1", to: "0", payload: [][]byte{[]byte("g0")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("g2")}},

		play{from: "0", to: "1", payload: [][]byte{[]byte("g10")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("g21")}},
		play{from: "2", to: "0", payload: [][]byte{[]byte("g02")}},
		play{from: "0", to: "1", payload: [][]byte{[]byte("h1")}},
		play{from: "1", to: "0", payload: [][]byte{[]byte("h0")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("h2")}},
	}

	for _, play := range playbook {
		if err := syncAndRunConsensus(cores, play.from, play.to, play.payload); err != nil {
			t.Fatal(err)
		}
	}
	return cores
}

func TestConsensus(t *testing.T) {
	cores := initConsensusHashgraph(t)

	c0 := cores["0"]
	c1 := cores["1"]
	c2 := cores["2"]

	if l := len(c0.GetConsensusEvents()); l != 6 {
		t.Fatalf("length of consensus should be 6 not %d", l)
	}

	core0Consensus := c0.GetConsensusEvents()
	core1Consensus := c1.GetConsensusEvents()
	core2Consensus := c2.GetConsensusEvents()

	for i, e := range core0Consensus {
		if core1Consensus[i] != e {
			t.Fatalf("core 1 consensus[%d] does not match core 0's", i)
		}
		if core2Consensus[i] != e {
			t.Fatalf("core 2 consensus[%d] does not match core 0's", i)
		}
	}
}

func TestOverSyncLimit(t *testing.T) {
	cores := initConsensusHashgraph(t)

	known := map[string]int{}

	syncLimit := 10

	//positive
	for i := 0; i < 3; i++ {
		known[strconv.Itoa(i)] = 1
	}

	c0 := cores["0"]

	if !c0.OverSyncLimit(known, syncLimit) {
		t.Fatalf("OverSyncLimit(%v, %v) should return true", known, syncLimit)
	}

	//negative
	for i := 0; i < 3; i++ {
		known[strconv.Itoa(i)] = 6
	}
	if c0.OverSyncLimit(known, syncLimit) {
		t.Fatalf("OverSyncLimit(%v, %v) should return false", known, syncLimit)
	}

	//edge
	known = map[string]int{
		"0": 2,
		"1": 3,
		"2": 3,
	}
	if c0.OverSyncLimit(known, syncLimit) {
		t.Fatalf("OverSyncLimit(%v, %v) should return false", known, syncLimit)
	}

}

/*

    |   |   |   |-----------------
	|   w31 |   | R3
	|	| \ |   |
    |   |  w32  |
    |   |   | \ |
    |   |   |  w33
    |   |   | / |-----------------
    |   |  g21  | R2
	|   | / |   |
	|   w21 |   |
	|	| \ |   |
    |   |   \   |
    |   |   | \ |
    |   |   |  w23
    |   |   | / |
    |   |  w22  |
	|   | / |   |-----------------
	|  f13  |   | R1
	|	| \ |   | LastConsensusRound for nodes 1, 2 and 3 because it is the last
    |   |   \   | Round that has all its witnesses decided
    |   |   | \ |
	|   |   |  w13
	|   |   | / |
	|   |  w12  |
    |   | / |   |
    |  w11  |   |
	|	| \ |   |-----------------
    |   |   \   | R0
    |   |   | \ |
    |   |   |  e32
    |   |   | / |
    |   |  e21  | All Events in Round 0 are Consensus Events.
    |   | / |   |
    |  e10  |   |
	| / |   |   |
   e0   e1  e2  e3
    0	1	2	3
*/
func initFFHashgraph(cores map[string]Core, t *testing.T) {
	playbook := []play{
		play{from: "0", to: "1", payload: [][]byte{[]byte("e10")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("e21")}},
		play{from: "2", to: "3", payload: [][]byte{[]byte("e32")}},
		play{from: "3", to: "1", payload: [][]byte{[]byte("w11")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("w12")}},
		play{from: "2", to: "3", payload: [][]byte{[]byte("w13")}},
		play{from: "3", to: "1", payload: [][]byte{[]byte("f13")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("w22")}},
		play{from: "2", to: "3", payload: [][]byte{[]byte("w23")}},
		play{from: "3", to: "1", payload: [][]byte{[]byte("w21")}},
		play{from: "1", to: "2", payload: [][]byte{[]byte("g21")}},
		play{from: "2", to: "3", payload: [][]byte{[]byte("w33")}},
		play{from: "3", to: "2", payload: [][]byte{[]byte("w32")}},
		play{from: "2", to: "1", payload: [][]byte{[]byte("w31")}},
	}

	for k, play := range playbook {
		if err := syncAndRunConsensus(cores, play.from, play.to, play.payload); err != nil {
			t.Fatalf("play %d: %s", k, err)
		}
	}
}

func TestConsensusFF(t *testing.T) {
	cores, _, _ := initCores(4, t)
	initFFHashgraph(cores, t)

	c0 := cores["0"]
	c1 := cores["1"]
	c2 := cores["2"]
	c3 := cores["3"]

	if r := c0.GetLastConsensusRoundIndex(); r != nil {
		disp := strconv.Itoa(*r)
		t.Fatalf("Cores[0] last consensus Round should be nil, not %s", disp)
	}

	if r := c1.GetLastConsensusRoundIndex(); r == nil || *r != 1 {
		disp := "nil"
		if r != nil {
			disp = strconv.Itoa(*r)
		}
		t.Fatalf("Cores[1] last consensus Round should be 1, not %s", disp)
	}

	if l := len(c0.GetConsensusEvents()); l != 0 {
		t.Fatalf("Node 0 should have 0 consensus events, not %d", l)
	}

	if l := len(c1.GetConsensusEvents()); l != 7 {
		t.Fatalf("Node 1 should have 7 consensus events, not %d", l)
	}

	core1Consensus := c1.GetConsensusEvents()
	core2Consensus := c2.GetConsensusEvents()
	core3Consensus := c3.GetConsensusEvents()

	for i, e := range core1Consensus {
		if core2Consensus[i] != e {
			t.Fatalf("Node 2 consensus[%d] does not match Node 1's", i)
		}
		if core3Consensus[i] != e {
			t.Fatalf("Node 3 consensus[%d] does not match Node 1's", i)
		}
	}
}

func synchronizeCores(cores map[string]Core, from string, to string, payload [][]byte) error {
	cTo := cores[to]
	cFrom := cores[from]
	knownByTo := cTo.KnownEvents()
	unknownByTo, err := cFrom.EventDiff(knownByTo)
	if err != nil {
		return err
	}

	unknownWire, err := cFrom.ToWire(unknownByTo)
	if err != nil {
		return err
	}

	cTo.AddTransactions(payload)

	return cTo.Sync(unknownWire)
}

func syncAndRunConsensus(cores map[string]Core, from string, to string, payload [][]byte) error {
	if err := synchronizeCores(cores, from, to, payload); err != nil {
		return err
	}
	cTo := cores[to]
	cTo.RunConsensus()
	return nil
}

func getName(index map[string]string, hash string) string {
	for name, h := range index {
		if h == hash {
			return name
		}
	}
	return fmt.Sprintf("%s not found", hash)
}
