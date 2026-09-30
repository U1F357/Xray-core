// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

import (
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// classicECN implements the feedback state of RFC 3168. It is deliberately
// separate from the fingerprint's SYN layout: advertising ECN obliges the
// endpoint to echo CE and respond to ECE for the lifetime of the connection.
// The zero value preserves upstream non-ECN behavior.
//
// +stateify savable
type classicECN struct {
	offered         bool
	enabled         bool
	echo            bool
	pendingCWR      bool
	reduced         bool
	recoveryEnd     seqnum.Value
	accurateOffered bool
	accurate        bool
	rxCE            uint8
	txACE           uint8
	ceSinceACK      uint8
	thirdACKPending bool
	thirdACKCode    uint8
	synCESeen       bool
	synCongestion   bool
	peerSYNSeq      seqnum.Value
	localSYNAck     seqnum.Value
	feedbackAck     seqnum.Value
	feedbackSeq     seqnum.Value
	feedbackTS      uint32
	feedbackSeen    bool
	ackOfACK        bool
	disableECT      bool
	synECN          byte
	forceACK        bool
	dsackPending    bool
	dsack           header.SACKBlock
	dsackContaining header.SACKBlock
}

func (c *classicECN) negotiate(flags header.TCPFlags, ae bool) {
	code := uint8(flags >> 6)
	if ae {
		code |= 4
	}
	if c.offered && c.accurateOffered && code >= 2 && code <= 6 {
		c.enabled, c.accurate = true, true
		c.rxCE, c.txACE = 5, 5
		c.synCongestion = code == 6
		expected := [4]uint8{2, 3, 4, 6}[c.synECN]
		c.disableECT = code != expected && code != 5 && !(code == 6 && c.synECN != 0)
	} else {
		c.enabled = c.offered && !ae && code == 1
	}
	c.offered, c.accurateOffered = false, false
}

func segmentECN(s *segment) byte {
	ip := s.pkt.NetworkHeader().Slice()
	switch s.pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		return ip[1] & 3
	case header.IPv6ProtocolNumber:
		return (ip[1] >> 4) & 3
	default:
		return 0
	}
}

func (c *classicECN) acceptSynACK(s *segment) {
	if !c.accurate {
		return
	}
	c.peerSYNSeq, c.localSYNAck = s.sequenceNumber, s.ackNumber
	c.thirdACKPending = true
	c.thirdACKCode = [4]uint8{2, 3, 4, 6}[segmentECN(s)]
	if segmentECN(s) == 3 && !c.synCESeen {
		c.rxCE++
		c.synCESeen = true
	}
	if !c.feedbackSeen {
		c.feedbackAck, c.feedbackSeq, c.feedbackTS = s.ackNumber, s.sequenceNumber, s.parsedOptions.TSVal
		c.feedbackSeen = true
	}
}

// prepare never marks pure ACKs, retransmissions, or resets ECT, and puts CWR
// only on new data. The caller consumes pendingCWR after a successful send.
func (c *classicECN) prepare(tf *tcpFields, newData bool) bool {
	if !c.enabled || tf.flags&(header.TCPFlagSyn|header.TCPFlagRst) != 0 {
		return false
	}
	if c.accurate {
		code := c.rxCE & 7
		if c.thirdACKPending && !newData {
			code = c.thirdACKCode
		}
		tf.flags = (tf.flags &^ (header.TCPFlagEce | header.TCPFlagCwr)) | header.TCPFlags(code&3)<<6
		tf.ae = code&4 != 0
		tf.accurate = true
		if newData && !c.disableECT {
			tf.tos = (tf.tos &^ 3) | 2
		}
		return false
	}
	if c.echo && tf.flags.Contains(header.TCPFlagAck) {
		tf.flags |= header.TCPFlagEce
	}
	if !newData {
		return false
	}
	tf.tos = (tf.tos &^ 3) | 2
	if c.pendingCWR {
		tf.flags |= header.TCPFlagCwr
		return true
	}
	return false
}

// +checklocks:e.mu
func (e *Endpoint) receiveECN(s *segment) {
	if !e.ecn.enabled || (e.snd != nil && e.snd.SndNxt.LessThan(s.ackNumber)) {
		return
	}
	if e.ecn.accurate {
		if segmentECN(s) == 3 {
			e.ecn.rxCE = (e.ecn.rxCE + 1) & 7
			e.ecn.ceSinceACK++
			// ACK each marked data packet. Pure ACKs are acknowledged only
			// once per three CE marks, avoiding an ACK-of-ACK feedback loop.
			if s.payloadSize() > 0 || e.ecn.ceSinceACK >= 3 {
				e.ecn.ackOfACK = s.payloadSize() == 0
				e.ecn.forceACK = true
			}
		}
		return
	}
	if s.flags.Contains(header.TCPFlagCwr) {
		e.ecn.echo = false
	}
	// RFC 3168 feeds back congestion on data, not pure ACKs. CE takes
	// precedence when the same packet also carries CWR.
	if s.payloadSize() == 0 {
		return
	}
	if segmentECN(s) == 3 {
		e.ecn.echo = true
	}
}

// +checklocks:s.ep.mu
func (s *sender) handleECNEcho(seg *segment) {
	c := &s.ep.ecn
	ack := seg.ackNumber
	if !c.enabled || ack.LessThan(s.SndUna) || s.SndNxt.LessThan(ack) {
		return
	}
	// Retire old sequence boundaries promptly, including on non-ECE ACKs,
	// so a long-lived connection remains correct across sequence wrap.
	if c.reduced && c.recoveryEnd.LessThan(ack) {
		c.reduced = false
	}
	congestion := seg.flags.Contains(header.TCPFlagEce)
	if c.accurate {
		congestion = s.accurateECNFeedback(seg)
	}
	if s.SndUna == s.SndNxt || !congestion || c.reduced {
		return
	}
	// Loss recovery already reduced the window for this flight. ECN must
	// not cause a second reduction for the same congestion episode.
	if !s.FastRecovery.Active {
		s.cc.HandleLossDetected()
		s.SndCwnd = min(s.SndCwnd, s.Ssthresh)
		s.SndCAAckCount = 0
	}
	c.reduced = true
	c.recoveryEnd = s.SndNxt
	c.pendingCWR = true
}

// reduceOnLoss shares the congestion episode boundary with ECN, so losing a
// packet from the CE-marked flight does not halve the window a second time.
// +checklocks:s.ep.mu
func (s *sender) reduceOnLoss() {
	c := &s.ep.ecn
	if !c.enabled {
		s.cc.HandleLossDetected()
		return
	}
	if !c.reduced || c.recoveryEnd.LessThan(s.SndUna) {
		s.cc.HandleLossDetected()
	}
	c.reduced = true
	c.recoveryEnd = s.SndNxt
	c.pendingCWR = true
}

// accurateECNFeedback ignores superseded feedback and conservatively assumes
// counter wrap when one ACK covers at least eight full-sized segments. This is
// the ACE-only safety approach of RFC 9768 Appendix A.2.1; no byte options or
// scalable/L4S congestion controller is claimed.
// +checklocks:s.ep.mu
func (s *sender) accurateECNFeedback(seg *segment) bool {
	c := &s.ep.ecn
	ack, seq := seg.ackNumber, seg.sequenceNumber
	if ack.LessThan(c.feedbackAck) {
		return false
	}
	advance := c.feedbackAck.LessThan(ack) || c.feedbackSeq.LessThan(seq) || seg.hasNewSACKInfo
	if seg.parsedOptions.TS {
		if int32(seg.parsedOptions.TSVal-c.feedbackTS) < 0 && ack == c.feedbackAck {
			return false
		}
		advance = advance || int32(seg.parsedOptions.TSVal-c.feedbackTS) > 0
	}
	if !advance {
		return false
	}
	if ack == c.feedbackAck && seq.LessThan(c.feedbackSeq) {
		return false
	}
	code := uint8(seg.flags >> 6)
	if seg.pkt.TransportHeader().Slice()[12]&1 != 0 {
		code |= 4
	}
	delta := int((code - c.txACE) & 7)
	packets := int(c.feedbackAck.Size(ack)) / max(1, s.MaxPayloadSize)
	if packets >= delta+8 {
		delta = packets - (packets-delta)%8
	}
	c.txACE = code
	c.feedbackAck, c.feedbackSeq, c.feedbackTS = ack, seq, seg.parsedOptions.TSVal
	return delta > 0
}
