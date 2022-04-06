package selectors

import "github.com/netsec-ethz/scion-apps/pkg/pan"

func isInterfaceOnPath(path pan.Path, inf pan.PathInterface) bool {
	for _, i := range path.Metadata.Interfaces {
		if i == inf {
			return true
		}
	}
	return false
}
