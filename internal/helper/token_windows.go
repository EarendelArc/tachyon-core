//go:build windows

package helper

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type tokenSecuritySnapshot struct {
	ServiceSIDPresent  bool
	RestrictedSIDCount int
}

func currentTokenSecurity() tokenSecuritySnapshot {
	token := windows.GetCurrentProcessToken()
	groups, err := token.GetTokenGroups()
	if err != nil {
		return tokenSecuritySnapshot{}
	}
	snapshot := tokenSecuritySnapshot{}
	for _, group := range groups.AllGroups() {
		if group.Sid != nil && strings.HasPrefix(group.Sid.String(), "S-1-5-80-") &&
			group.Attributes&windows.SE_GROUP_ENABLED != 0 {
			snapshot.ServiceSIDPresent = true
		}
	}
	snapshot.RestrictedSIDCount = restrictedSIDCount(token)
	return snapshot
}

func restrictedSIDCount(token windows.Token) int {
	var required uint32
	err := windows.GetTokenInformation(token, windows.TokenRestrictedSids, nil, 0, &required)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || required == 0 {
		return 0
	}
	buffer := make([]byte, required)
	if err := windows.GetTokenInformation(token, windows.TokenRestrictedSids, &buffer[0], required, &required); err != nil {
		return 0
	}
	groups := (*windows.Tokengroups)(unsafe.Pointer(&buffer[0]))
	return len(groups.AllGroups())
}
