package outbound

// Startup capture planning also applies to relay-only nodes without freedom.
func (c *Config) RequiresTCPFingerprintCapture() bool { return c.TcpFingerprintForward }
