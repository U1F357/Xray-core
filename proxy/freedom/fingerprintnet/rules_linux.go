//go:build linux

package fingerprintnet

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// Preserve the previous "no forwarding" behavior for unrelated traffic when
// enabling forwarding on a real interface. Only established replies to leased
// userspace stacks may pass this early forward hook.
func updateForwardingGuard(index int, lease *forwardingLease, owners map[string]owner) error {
	if lease.Original != "0" {
		return nil
	}
	c := &nftables.Conn{}
	table := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: fmt.Sprintf("xray_fpg_%d", index)}
	if len(lease.Owners) == 0 {
		tables, err := c.ListTablesOfFamily(nftables.TableFamilyIPv4)
		if err != nil {
			return err
		}
		for _, existing := range tables {
			if existing.Name == table.Name {
				c.DelTable(existing)
			}
		}
		return c.Flush()
	}
	c.AddTable(table)
	chain := c.AddChain(&nftables.Chain{Name: "forward", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityRef(-10)})
	c.FlushChain(chain)
	for token := range lease.Owners {
		o := owners[token]
		rules := append(interfaceMatch(expr.MetaKeyIIFNAME, lease.Name), incoming(o)...)
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, UserData: []byte(table.Name), Exprs: append(rules, &expr.Verdict{Kind: expr.VerdictAccept})})
	}
	c.AddRule(&nftables.Rule{Table: table, Chain: chain, UserData: []byte(table.Name), Exprs: append(interfaceMatch(expr.MetaKeyIIFNAME, lease.Name), &expr.Verdict{Kind: expr.VerdictDrop})})
	return c.Flush()
}

func interfaceMatch(key expr.MetaKey, name string) []expr.Any {
	nameBytes := make([]byte, 16)
	copy(nameBytes, name)
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nameBytes}}
}

func addressMatch(source bool, address net.IP) []expr.Any {
	offset := uint32(16)
	if source {
		offset = 12
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}}, // NFPROTO_IPV4
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: address.To4()},
	}
}

func outgoing(o owner) []expr.Any {
	r := interfaceMatch(expr.MetaKeyIIFNAME, o.Device)
	return append(r, addressMatch(true, net.ParseIP(o.Address))...)
}

func incoming(o owner) []expr.Any {
	r := interfaceMatch(expr.MetaKeyOIFNAME, o.Device)
	r = append(r, addressMatch(false, net.ParseIP(o.Address))...)
	return append(r,
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	)
}

func installRules(o owner) error {
	c := &nftables.Conn{}
	existing, err := c.ListChains()
	if err != nil {
		return err
	}
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: o.Table})
	c.AddChain(&nftables.Chain{Name: "prerouting", Table: table, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest})
	post := c.AddChain(&nftables.Chain{Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource})
	c.AddRule(&nftables.Rule{Table: table, Chain: post, UserData: []byte(o.Table), Exprs: append(outgoing(o), &expr.Masq{})})
	forward := c.AddChain(&nftables.Chain{Name: "forward", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter})
	// An ACCEPT in a separate base chain cannot override another base chain's
	// DROP policy. Insert only our TUN-scoped exceptions in existing IPv4/inet
	// forwarding chains; keep every pre-existing rule and policy intact.
	existing = append(existing, forward)
	for _, chain := range existing {
		if strings.HasPrefix(chain.Table.Name, "xray_fpg_") {
			continue
		}
		if chain.Hooknum == nil || *chain.Hooknum != *nftables.ChainHookForward {
			continue
		}
		if chain.Table.Family != nftables.TableFamilyIPv4 && chain.Table.Family != nftables.TableFamilyINet {
			continue
		}
		if chain.Type != nftables.ChainTypeFilter {
			continue
		}
		for _, match := range [][]expr.Any{outgoing(o), incoming(o)} {
			c.InsertRule(&nftables.Rule{Table: chain.Table, Chain: chain, UserData: []byte(o.Table), Exprs: append(match, &expr.Verdict{Kind: expr.VerdictAccept})})
		}
	}
	return c.Flush()
}

func removeRules(tableName string) error {
	if tableName == "" {
		return nil
	}
	c := &nftables.Conn{}
	chains, err := c.ListChains()
	if err != nil {
		return err
	}
	for _, chain := range chains {
		if chain.Table.Name == tableName {
			continue
		}
		if chain.Hooknum == nil || *chain.Hooknum != *nftables.ChainHookForward {
			continue
		}
		rules, err := c.GetRules(chain.Table, chain)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if bytes.Equal(rule.UserData, []byte(tableName)) {
				if err := c.DelRule(rule); err != nil {
					return err
				}
			}
		}
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	for _, table := range tables {
		if table.Name == tableName {
			c.DelTable(table)
		}
	}
	return c.Flush()
}
