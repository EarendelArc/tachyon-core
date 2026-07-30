package helper

// diagnosticFile is opened once during helper startup and kept for the whole
// runtime. Implementations must not reopen the configured path for updates.
type diagnosticFile interface {
	Write([]byte) error
	Close() error
}
