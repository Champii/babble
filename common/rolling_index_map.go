package common

type RollingIndexMap struct {
	size    int
	keys    []string
	mapping map[string]*RollingIndex
}

func NewRollingIndexMap(size int, keys []string) *RollingIndexMap {
	items := make(map[string]*RollingIndex)
	for _, key := range keys {
		items[key] = NewRollingIndex(size)
	}
	return &RollingIndexMap{
		size:    size,
		keys:    keys,
		mapping: items,
	}
}

//return key items with index > skip
func (rim *RollingIndexMap) Get(key string, skipIndex int) ([]interface{}, error) {
	items, ok := rim.mapping[key]
	if !ok {
		return nil, NewStoreErr(KeyNotFound, key)
	}

	cached, err := items.Get(skipIndex)
	if err != nil {
		return nil, err
	}

	return cached, nil
}

func (rim *RollingIndexMap) GetItem(key string, index int) (interface{}, error) {
	return rim.mapping[key].GetItem(index)
}

func (rim *RollingIndexMap) GetLast(key string) (interface{}, error) {
	pe, ok := rim.mapping[key]
	if !ok {
		return nil, NewStoreErr(KeyNotFound, key)
	}
	cached, _ := pe.GetLastWindow()
	if len(cached) == 0 {
		return "", nil
	}
	return cached[len(cached)-1], nil
}

func (rim *RollingIndexMap) Set(key string, item interface{}, index int) error {
	items, ok := rim.mapping[key]
	if !ok {
		items = NewRollingIndex(rim.size)
		rim.mapping[key] = items
	}
	return items.Set(item, index)
}

//returns [key] => lastKnownIndex
func (rim *RollingIndexMap) Known() map[string]int {
	known := make(map[string]int)
	for k, items := range rim.mapping {
		_, lastIndex := items.GetLastWindow()
		known[k] = lastIndex
	}
	return known
}

func (rim *RollingIndexMap) Reset() error {
	items := make(map[string]*RollingIndex)
	for _, key := range rim.keys {
		items[key] = NewRollingIndex(rim.size)
	}
	rim.mapping = items
	return nil
}
