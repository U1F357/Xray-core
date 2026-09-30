package session

import "context"

type TCPFingerprintPolicy struct {
	Source       string
	TrustedUsers []string
	OnMissing    string
}
type fingerprintPolicyKey struct{}

func ContextWithTCPFingerprintPolicy(ctx context.Context, p *TCPFingerprintPolicy) context.Context {
	return context.WithValue(ctx, fingerprintPolicyKey{}, p)
}
func TCPFingerprintPolicyFromContext(ctx context.Context) *TCPFingerprintPolicy {
	p, _ := ctx.Value(fingerprintPolicyKey{}).(*TCPFingerprintPolicy)
	return p
}
