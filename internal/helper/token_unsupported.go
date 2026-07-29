//go:build !windows

package helper

type tokenSecuritySnapshot struct {
	ServiceSIDPresent  bool
	RestrictedSIDCount int
}

func currentTokenSecurity() tokenSecuritySnapshot { return tokenSecuritySnapshot{} }
