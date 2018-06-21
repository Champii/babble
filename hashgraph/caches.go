package hashgraph

import (
	"fmt"

	cm "github.com/champii/babble/common"
)

type Key struct {
	x string
	y string
}

func (k Key) ToString() string {
	return fmt.Sprintf("{%s, %s}", k.x, k.y)
}

type ParentRoundInfo struct {
	round  int
	isRoot bool
}

func NewBaseParentRoundInfo() ParentRoundInfo {
	return ParentRoundInfo{
		round:  -1,
		isRoot: false,
	}
}

func getValues(mapping map[string]string) []string {
	keys := make([]string, len(mapping))
	i := 0
	for _, id := range mapping {
		keys[i] = id
		i++
	}
	return keys
}

//------------------------------------------------------------------------------

type ParticipantEventsCache struct {
	participants map[string]string
	rim          *cm.RollingIndexMap
}

func NewParticipantEventsCache(size int, participants map[string]string) *ParticipantEventsCache {
	return &ParticipantEventsCache{
		participants: participants,
		rim:          cm.NewRollingIndexMap(size, getValues(participants)),
	}
}

func (pec *ParticipantEventsCache) participantID(participant string) (string, error) {
	return participant, nil
}

func (pec *ParticipantEventsCache) AddParticipant(participant string) {
	pec.participants[participant] = participant

	pec.Set(participant, participant, 0)
	pec.rim.AddParticipant(participant)

}

//return participant events with index > skip
func (pec *ParticipantEventsCache) Get(participant string, skipIndex int) ([]string, error) {
	pe, err := pec.rim.Get(participant, skipIndex)
	if err != nil {
		return []string{}, err
	}

	res := make([]string, len(pe))
	for k := 0; k < len(pe); k++ {
		res[k] = pe[k].(string)
	}
	return res, nil
}

func (pec *ParticipantEventsCache) GetItem(participant string, index int) (string, error) {
	item, err := pec.rim.GetItem(participant, index)
	if err != nil {
		return "", err
	}
	return item.(string), nil
}

func (pec *ParticipantEventsCache) GetLast(participant string) (string, error) {
	last, err := pec.rim.GetLast(participant)
	if err != nil {
		return "", err
	}

	return last.(string), nil
}

func (pec *ParticipantEventsCache) Set(participant string, hash string, index int) error {
	return pec.rim.Set(participant, hash, index)
}

//returns [participant id] => lastKnownIndex
func (pec *ParticipantEventsCache) Known() map[string]int {
	return pec.rim.Known()
}

func (pec *ParticipantEventsCache) Reset() error {
	return pec.rim.Reset()
}

//------------------------------------------------------------------------------

type ParticipantBlockSignaturesCache struct {
	participants map[string]string
	rim          *cm.RollingIndexMap
}

func NewParticipantBlockSignaturesCache(size int, participants map[string]string) *ParticipantBlockSignaturesCache {
	return &ParticipantBlockSignaturesCache{
		participants: participants,
		rim:          cm.NewRollingIndexMap(size, getValues(participants)),
	}
}

// func (psc *ParticipantBlockSignaturesCache) participantID(participant string) (string, error) {
// id, ok := psc.participants[participant]
// if !ok {
// 	return -1, cm.NewStoreErr(cm.UnknownParticipant, participant)
// }
// return id, nil
// }

//return participant BlockSignatures where index > skip
func (psc *ParticipantBlockSignaturesCache) Get(participant string, skipIndex int) ([]BlockSignature, error) {
	ps, err := psc.rim.Get(participant, skipIndex)
	if err != nil {
		return []BlockSignature{}, err
	}

	res := make([]BlockSignature, len(ps))
	for k := 0; k < len(ps); k++ {
		res[k] = ps[k].(BlockSignature)
	}
	return res, nil
}

func (psc *ParticipantBlockSignaturesCache) GetItem(participant string, index int) (BlockSignature, error) {
	item, err := psc.rim.GetItem(participant, index)
	if err != nil {
		return BlockSignature{}, err
	}
	return item.(BlockSignature), nil
}

func (psc *ParticipantBlockSignaturesCache) GetLast(participant string) (BlockSignature, error) {
	last, err := psc.rim.GetLast(psc.participants[participant])
	if err != nil {
		return BlockSignature{}, err
	}
	return last.(BlockSignature), nil
}

func (psc *ParticipantBlockSignaturesCache) Set(participant string, sig BlockSignature) error {
	return psc.rim.Set(participant, sig, sig.Index)
}

//returns [participant id] => last BlockSignature Index
func (psc *ParticipantBlockSignaturesCache) Known() map[string]int {
	return psc.rim.Known()
}

func (psc *ParticipantBlockSignaturesCache) Reset() error {
	return psc.rim.Reset()
}
