package transport

import (
	"bytes"
	"encoding/binary"
	"testing"

	"w33d-tunnel/pkg/protocol"
)

func wrapFECPacket(group uint64, index byte, payload []byte) []byte {
	packet := make([]byte, 9+len(payload))
	binary.BigEndian.PutUint64(packet[0:8], group)
	packet[8] = index
	copy(packet[9:], payload)
	return packet
}

func buildFECBlock(t *testing.T, group uint64) ([][]byte, [][]byte, [][]byte) {
	t.Helper()

	enc, err := NewFECEncoder()
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	dataPayloads := make([][]byte, FECDataShards)
	dataPackets := make([][]byte, FECDataShards)

	var parityShards [][]byte
	for i := 0; i < FECDataShards; i++ {
		payload := []byte{byte(i), byte(i + 1), byte(i + 2), byte(i + 3)}
		dataPayloads[i] = payload
		dataPackets[i] = wrapFECPacket(group, byte(i), payload)

		shards, err := enc.Encode(payload)
		if err != nil {
			t.Fatalf("encode failed at %d: %v", i, err)
		}
		if i < FECDataShards-1 && shards != nil {
			t.Fatalf("unexpected parity before full block")
		}
		if i == FECDataShards-1 {
			parityShards = shards
		}
	}

	if len(parityShards) != FECParityShards {
		t.Fatalf("expected %d parity shards, got %d", FECParityShards, len(parityShards))
	}

	parityPackets := make([][]byte, FECParityShards)
	for i := 0; i < FECParityShards; i++ {
		parityPackets[i] = wrapFECPacket(group, byte(FECDataShards+i), parityShards[i])
	}

	return dataPayloads, dataPackets, parityPackets
}

func collectRecoveredByIndex(dec *FECDecoder, arrivals [][]byte) map[byte][]byte {
	recovered := map[byte][]byte{}
	for _, pkt := range arrivals {
		flags := uint8(protocol.FlagData)
		if int(pkt[8]) >= FECDataShards {
			flags = uint8(protocol.FlagFEC)
		}
		out, err := dec.HandlePacket(pkt, protocol.Header{Flags: flags})
		if err != nil {
			continue
		}
		for _, rp := range out {
			idx := rp[8]
			recovered[idx] = rp[9:]
		}
	}
	return recovered
}

func TestFECRecoverSingleLoss(t *testing.T) {
	group := uint64(1)
	payloads, dataPackets, parityPackets := buildFECBlock(t, group)

	dec, err := NewFECDecoder()
	if err != nil {
		t.Fatalf("failed to create decoder: %v", err)
	}

	lost := 3
	var arrivals [][]byte
	for i, p := range dataPackets {
		if i == lost {
			continue
		}
		arrivals = append(arrivals, p)
	}
	arrivals = append(arrivals, parityPackets...)

	recovered := collectRecoveredByIndex(dec, arrivals)
	data, ok := recovered[byte(lost)]
	if !ok {
		t.Fatalf("expected recovery for index %d", lost)
	}
	if !bytes.HasPrefix(data, payloads[lost]) {
		t.Fatalf("recovered payload mismatch for index %d", lost)
	}
}

func TestFECRecoverTripleLoss(t *testing.T) {
	group := uint64(2)
	payloads, dataPackets, parityPackets := buildFECBlock(t, group)

	dec, err := NewFECDecoder()
	if err != nil {
		t.Fatalf("failed to create decoder: %v", err)
	}

	lost := map[int]bool{1: true, 4: true, 7: true}
	var arrivals [][]byte
	for i, p := range dataPackets {
		if lost[i] {
			continue
		}
		arrivals = append(arrivals, p)
	}
	arrivals = append(arrivals, parityPackets...)

	recovered := collectRecoveredByIndex(dec, arrivals)
	for idx := range lost {
		data, ok := recovered[byte(idx)]
		if !ok {
			t.Fatalf("expected recovery for index %d", idx)
		}
		if !bytes.HasPrefix(data, payloads[idx]) {
			t.Fatalf("recovered payload mismatch for index %d", idx)
		}
	}
}

func TestFECRecoverWithOutOfOrderParityArrival(t *testing.T) {
	group := uint64(3)
	payloads, dataPackets, parityPackets := buildFECBlock(t, group)

	dec, err := NewFECDecoder()
	if err != nil {
		t.Fatalf("failed to create decoder: %v", err)
	}

	lost := 5
	var arrivals [][]byte
	arrivals = append(arrivals, parityPackets[0]) // parity arrives early
	for i, p := range dataPackets {
		if i == lost {
			continue
		}
		arrivals = append(arrivals, p)
	}
	arrivals = append(arrivals, parityPackets[1], parityPackets[2])

	recovered := collectRecoveredByIndex(dec, arrivals)
	data, ok := recovered[byte(lost)]
	if !ok {
		t.Fatalf("expected recovery for index %d", lost)
	}
	if !bytes.HasPrefix(data, payloads[lost]) {
		t.Fatalf("recovered payload mismatch for index %d", lost)
	}
}
