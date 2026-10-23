package executors

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// AWS EventStream binary framing — port of open-sse/utils/awsEventStream.js
// (itself extracted from the kiro executor). Frame layout:
// [totalLength u32][headersLength u32][preludeCrc u32][headers][payload][messageCrc u32]
// CRC is CRC-32 IEEE (JS table polynomial 0xedb88320 == crc32.IEEE).

const (
	eventStreamMaxMessageBytes = 16 * 1024 * 1024 // generous bound; JS AWS_EVENTSTREAM limits are config-driven
	eventStreamMaxHeadersBytes = 128 * 1024
)

var crcTable = crc32.MakeTable(crc32.IEEE)

func crc32IEEE(b []byte) uint32 { return crc32.Checksum(b, crcTable) }

// EventFrame is one decoded EventStream frame. Header values are string,
// bool, or numeric depending on the wire type; string headers (type 7) are
// the only ones the chat paths consume.
type EventFrame struct {
	Headers map[string]any
	Payload map[string]any // decoded JSON payload, nil when empty/non-JSON
	Raw     []byte         // raw payload bytes
}

func (f *EventFrame) HeaderString(name string) string {
	if f == nil {
		return ""
	}
	if s, ok := f.Headers[name].(string); ok {
		return s
	}
	return ""
}

// parseEventFrame decodes exactly one frame (len(data) must equal the
// frame's declared total length). It throws on any integrity failure rather
// than returning partial data — a silently truncated frame becomes a
// silently truncated model response (awsEventStream.js).
func parseEventFrame(data []byte) (*EventFrame, error) {
	if len(data) < 16 {
		return nil, errors.New("AWS EventStream frame is shorter than 16 bytes")
	}
	totalLength := int(binary.BigEndian.Uint32(data[0:4]))
	headersLength := int(binary.BigEndian.Uint32(data[4:8]))
	if totalLength != len(data) {
		return nil, errors.New("AWS EventStream frame length does not match its prelude")
	}
	if totalLength > eventStreamMaxMessageBytes || headersLength > eventStreamMaxHeadersBytes ||
		headersLength > totalLength-16 {
		return nil, errors.New("AWS EventStream frame bounds are invalid")
	}
	if binary.BigEndian.Uint32(data[8:12]) != crc32IEEE(data[0:8]) {
		return nil, errors.New("AWS EventStream prelude CRC mismatch")
	}
	if binary.BigEndian.Uint32(data[totalLength-4:totalLength]) != crc32IEEE(data[0:totalLength-4]) {
		return nil, errors.New("AWS EventStream message CRC mismatch")
	}

	headers := map[string]any{}
	offset := 12
	headerEnd := offset + headersLength
	require := func(n int) error {
		if offset+n > headerEnd {
			return errors.New("AWS EventStream header exceeds its declared bounds")
		}
		return nil
	}
	for offset < headerEnd {
		if err := require(1); err != nil {
			return nil, err
		}
		nameLen := int(data[offset])
		offset++
		if err := require(nameLen + 1); err != nil {
			return nil, err
		}
		name := string(data[offset : offset+nameLen])
		offset += nameLen
		if _, dup := headers[name]; dup {
			return nil, fmt.Errorf("AWS EventStream contains duplicate header: %s", name)
		}
		typ := data[offset]
		offset++
		switch typ {
		case 0, 1: // bool false / true
			headers[name] = typ == 0
		case 2: // byte
			if err := require(1); err != nil {
				return nil, err
			}
			headers[name] = int8(data[offset])
			offset++
		case 3: // short
			if err := require(2); err != nil {
				return nil, err
			}
			headers[name] = int16(binary.BigEndian.Uint16(data[offset:]))
			offset += 2
		case 4: // int
			if err := require(4); err != nil {
				return nil, err
			}
			headers[name] = int32(binary.BigEndian.Uint32(data[offset:]))
			offset += 4
		case 5, 8: // long / timestamp (8 bytes, skipped like the JS)
			if err := require(8); err != nil {
				return nil, err
			}
			offset += 8
		case 6, 7: // byte array / string
			if err := require(2); err != nil {
				return nil, err
			}
			valueLen := int(binary.BigEndian.Uint16(data[offset:]))
			offset += 2
			if err := require(valueLen); err != nil {
				return nil, err
			}
			v := data[offset : offset+valueLen]
			if typ == 7 {
				headers[name] = string(v)
			} else {
				cp := make([]byte, len(v))
				copy(cp, v)
				headers[name] = cp
			}
			offset += valueLen
		case 9: // uuid (16 bytes, skipped like the JS)
			if err := require(16); err != nil {
				return nil, err
			}
			offset += 16
		default:
			return nil, fmt.Errorf("AWS EventStream header %s has unknown type %d", name, typ)
		}
	}

	payloadBytes := data[headerEnd : totalLength-4]
	frame := &EventFrame{Headers: headers, Raw: payloadBytes}
	if len(payloadBytes) == 0 || len(bytes.TrimSpace(payloadBytes)) == 0 {
		return frame, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("AWS EventStream payload is not valid JSON (%v)", err)
	}
	frame.Payload = payload
	return frame, nil
}

// encodeEventFrame builds one frame with string headers (type 7). Used by
// tests/fixtures — nothing in the request path emits EventStream (mirrors
// the JS comment on encodeEventFrame).
func encodeEventFrame(headers map[string]string, payload any) []byte {
	var headerBuf bytes.Buffer
	// Deterministic order for tests: sort keys.
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, name := range keys {
		value := headers[name]
		headerBuf.WriteByte(byte(len(name)))
		headerBuf.WriteString(name)
		headerBuf.WriteByte(7)
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(value)))
		headerBuf.Write(lb[:])
		headerBuf.WriteString(value)
	}
	var payloadBytes []byte
	if payload != nil {
		payloadBytes, _ = json.Marshal(payload)
	}
	totalLength := 16 + headerBuf.Len() + len(payloadBytes)
	frame := make([]byte, totalLength)
	binary.BigEndian.PutUint32(frame[0:4], uint32(totalLength))
	binary.BigEndian.PutUint32(frame[4:8], uint32(headerBuf.Len()))
	binary.BigEndian.PutUint32(frame[8:12], crc32IEEE(frame[0:8]))
	copy(frame[12:], headerBuf.Bytes())
	copy(frame[12+headerBuf.Len():], payloadBytes)
	binary.BigEndian.PutUint32(frame[totalLength-4:], crc32IEEE(frame[0:totalLength-4]))
	return frame
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// eventStreamReader incrementally decodes frames from a stream.
type eventStreamReader struct {
	r   io.Reader
	buf []byte
	err error
}

// next returns the next frame, or io.EOF at a clean frame boundary.
func (e *eventStreamReader) next() (*EventFrame, error) {
	for {
		if len(e.buf) >= 4 {
			total := int(binary.BigEndian.Uint32(e.buf[0:4]))
			if total < 16 || total > eventStreamMaxMessageBytes {
				return nil, errors.New("AWS EventStream frame bounds are invalid")
			}
			if len(e.buf) >= total {
				frameBytes := e.buf[:total]
				e.buf = e.buf[total:]
				return parseEventFrame(frameBytes)
			}
		}
		if e.err != nil {
			if e.err == io.EOF && len(e.buf) == 0 {
				return nil, io.EOF
			}
			if e.err == io.EOF {
				return nil, errors.New("AWS EventStream ended with a truncated frame")
			}
			return nil, e.err
		}
		chunk := make([]byte, 32*1024)
		n, err := e.r.Read(chunk)
		if n > 0 {
			e.buf = append(e.buf, chunk[:n]...)
		}
		if err != nil {
			e.err = err
		}
	}
}
