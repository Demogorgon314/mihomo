package tunnel

import (
	"fmt"
	"slices"

	C "github.com/metacubex/mihomo/constant"
)

// InspectRoute matches a synthetic destination without opening a connection.
// IP rules may resolve DNS. Process and payload sniffing rules cannot be
// evaluated without an actual application's connection. The returned chain is
// leaf first; automatic groups may select differently on a later connection.
func InspectRoute(target string) (C.Rule, []string, error) {
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.INNER}
	if err := metadata.SetRemoteAddress(target); err != nil {
		return nil, nil, err
	}
	fixMetadata(metadata)
	if err := preHandleMetadata(metadata); err != nil {
		return nil, nil, err
	}
	proxy, rule, err := resolveMetadata(metadata)
	if err != nil {
		return nil, nil, err
	}
	var chain []string
	for proxy != nil {
		if slices.Contains(chain, proxy.Name()) || len(chain) >= 64 {
			return nil, nil, fmt.Errorf("proxy group cycle in route")
		}
		chain = append(chain, proxy.Name())
		proxy = proxy.Unwrap(metadata, false)
	}
	if len(chain) == 0 {
		return nil, nil, fmt.Errorf("no proxy for route")
	}
	slices.Reverse(chain)
	return rule, chain, nil
}
