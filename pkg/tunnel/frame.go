package tunnel

import (
	"encoding/binary"
	"errors"
)

// Cmd types
const (
	CmdData           = 0
	CmdConnect        = 1
	CmdConnectSuccess = 2
	CmdConnectFail    = 3
	CmdClose          = 4
	CmdUDP            = 5 // UDP Datagram payload
)

// Frame represents a multiplexed stream frame.
// Format: [StreamID 4b] [Cmd 1b] [Data...]
type Frame struct {
	StreamID uint32
	Cmd      uint8
	Data     []byte
}

// Marshal serializes the frame.
func (f *Frame) Marshal() []byte {
	buf := make([]byte, 5+len(f.Data))
	binary.BigEndian.PutUint32(buf[0:4], f.StreamID)
	buf[4] = f.Cmd
	copy(buf[5:], f.Data)
	return buf
}

// UnmarshalFrame parses a frame.
func UnmarshalFrame(data []byte) (*Frame, error) {
	if len(data) < 5 {
		return nil, errors.New("frame too short")
	}
	return &Frame{
		StreamID: binary.BigEndian.Uint32(data[0:4]),
		Cmd:      data[4],
		Data:     data[5:],
	}, nil
}
