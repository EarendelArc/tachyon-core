//go:build windows

package capturedudp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func NewNamedPipeClient(config NamedPipeClientConfig, onReply func(context.Context, NamedPipeDelivery) error) (NamedPipeClient, error) {
	return newNamedPipeClient(config, onReply)
}

func openNamedPipeClient(ctx context.Context, config NamedPipeClientConfig) (namedPipeClientConnection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	namePointer, err := windows.UTF16PtrFromString(config.Name)
	if err != nil {
		return nil, fmt.Errorf("encode named pipe name: %w", err)
	}
	handle, openErr := windows.CreateFile(namePointer, namedPipeClientAccess, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IMPERSONATION, 0)
	if openErr != nil {
		return nil, openErr
	}
	connection := &windowsPipeConnection{handle: handle}
	if err := verifyNamedPipeServerIdentity(handle, config); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func verifyNamedPipeServerIdentity(handle windows.Handle, config NamedPipeClientConfig) error {
	var processID uint32
	if err := windows.GetNamedPipeServerProcessId(handle, &processID); err != nil || processID == 0 {
		return fmt.Errorf("%w: get named pipe server process ID: %v", ErrNamedPipeIdentity, err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, processID)
	if err != nil {
		return fmt.Errorf("%w: open server process: %v", ErrNamedPipeIdentity, err)
	}
	defer windows.CloseHandle(process)
	var creationStart, exitTime, kernelTime, userTime windows.Filetime
	if err := windows.GetProcessTimes(process, &creationStart, &exitTime, &kernelTime, &userTime); err != nil {
		return fmt.Errorf("%w: get server process creation time: %v", ErrNamedPipeIdentity, err)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("%w: open server process token: %v", ErrNamedPipeIdentity, err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("%w: read server SID: %v", ErrNamedPipeIdentity, err)
	}
	serverSID := user.User.Sid.String()
	allowed := false
	for _, configured := range config.ServerSIDs {
		if serverSID == configured {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("%w: server SID %s is not allowlisted", ErrNamedPipeIdentity, serverSID)
	}
	actualIntegrity, err := tokenIntegrityRIDForClient(token)
	if err != nil || actualIntegrity < config.MinimumServerIntegrityRID {
		return fmt.Errorf("%w: server integrity 0x%x is below 0x%x: %v", ErrNamedPipeIdentity, actualIntegrity, config.MinimumServerIntegrityRID, err)
	}
	imagePath, err := processImagePath(process)
	if err != nil {
		return fmt.Errorf("%w: query server image path: %v", ErrNamedPipeIdentity, err)
	}
	imageFile, finalImagePath, err := openImageFile(imagePath)
	if err != nil {
		return fmt.Errorf("%w: open server image file: %v", ErrNamedPipeIdentity, err)
	}
	defer windows.CloseHandle(imageFile)
	trustedPath, err := filepath.Abs(config.TrustedServerBinary)
	if err != nil {
		return fmt.Errorf("%w: resolve trusted image path: %v", ErrNamedPipeIdentity, err)
	}
	trustedFile, finalTrustedPath, err := openImageFile(trustedPath)
	if err != nil {
		return fmt.Errorf("%w: open trusted image file: %v", ErrNamedPipeIdentity, err)
	}
	defer windows.CloseHandle(trustedFile)
	if !strings.EqualFold(filepath.Clean(finalImagePath), filepath.Clean(finalTrustedPath)) {
		return fmt.Errorf("%w: server final image path %q does not match trusted %q", ErrNamedPipeIdentity, finalImagePath, finalTrustedPath)
	}
	hash, err := sha256FileHandle(imageFile)
	if err != nil || !strings.EqualFold(hash, config.TrustedServerSHA256) {
		return fmt.Errorf("%w: server image handle hash does not match trusted immutable hash: %v", ErrNamedPipeIdentity, err)
	}
	var creationEnd windows.Filetime
	if err := windows.GetProcessTimes(process, &creationEnd, &exitTime, &kernelTime, &userTime); err != nil {
		return fmt.Errorf("%w: recheck server process creation time: %v", ErrNamedPipeIdentity, err)
	}
	var processIDEnd uint32
	if err := windows.GetNamedPipeServerProcessId(handle, &processIDEnd); err != nil || processIDEnd != processID || creationStart != creationEnd {
		return fmt.Errorf("%w: server process identity changed during verification", ErrNamedPipeIdentity)
	}
	return nil
}

func openImageFile(path string) (windows.Handle, string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, "", err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, "", err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, "", err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return 0, "", errors.New("image file is a reparse point")
	}
	finalPath, err := finalPathByHandle(handle)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return 0, "", err
	}
	return handle, finalPath, nil
}

func finalPathByHandle(handle windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_PATH)
	for len(buffer) <= 32768 {
		size, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err == nil {
			return windows.UTF16ToString(buffer[:size]), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", err
		}
		buffer = make([]uint16, len(buffer)*2)
	}
	return "", errors.New("final image path exceeds maximum length")
}

func processImagePath(process windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_PATH)
	for len(buffer) <= 32768 {
		size := uint32(len(buffer))
		err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size)
		if err == nil {
			return windows.UTF16ToString(buffer[:size]), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", err
		}
		buffer = make([]uint16, len(buffer)*2)
	}
	return "", errors.New("server image path exceeds maximum length")
}

func tokenIntegrityRIDForClient(token windows.Token) (uint32, error) {
	var required uint32
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &required)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || required == 0 {
		return 0, err
	}
	buffer := make([]byte, required)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buffer[0], required, &required); err != nil {
		return 0, err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	if label.Label.Sid == nil || label.Label.Sid.SubAuthorityCount() == 0 {
		return 0, errors.New("server token has no integrity SID")
	}
	return label.Label.Sid.SubAuthority(uint32(label.Label.Sid.SubAuthorityCount() - 1)), nil
}

func sha256FileHandle(handle windows.Handle) (string, error) {
	hasher := sha256.New()
	buffer := make([]byte, 64*1024)
	for {
		var read uint32
		if err := windows.ReadFile(handle, buffer, &read, nil); err != nil {
			return "", err
		}
		if read == 0 {
			break
		}
		if _, err := hasher.Write(buffer[:read]); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
