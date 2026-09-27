//go:build !linux

package freedom

import "fmt"

func newFingerprintDialer(*Config) (fingerprintDialer, error) {
	return nil, fmt.Errorf("freedom tcpFingerprint currently requires Linux")
}
