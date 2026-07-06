//go:build !windows

package doctor

func fillWindowsFacts(facts *PlatformFacts) {
	_ = facts
}
