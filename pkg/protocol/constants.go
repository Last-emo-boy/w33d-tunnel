package protocol

const (
	// KeySize is the size of X25519 keys and ChaCha20Poly1305 keys.
	KeySize = 32
	// NonceSize is the size of ChaCha20Poly1305 nonce.
	NonceSize = 12
	// TagSize is the size of Poly1305 tag.
	TagSize = 16
	// AuthTagSize is the size of the truncated HMAC tag in Handshake Initiation.
	AuthTagSize = 16

	// Handshake Initiation Packet Constants
	// MinHandshakeSize is an example minimum size for handshake packets.
	MinHandshakeSize = 64
	// MaxHandshakeSize is an example maximum size for handshake packets.
	MaxHandshakeSize = 300

	// Protocol Flags
	FlagData  = 1 << 0 // 0x01
	FlagAck   = 1 << 1 // 0x02
	FlagRekey = 1 << 2 // 0x04
	FlagClose = 1 << 3 // 0x08
	FlagPad   = 1 << 4 // 0x10

	// MTU related
	DefaultMTU     = 1400 // Safe UDP payload size
	MaxPayloadSize = 65535

	// Timeouts
	HandshakeTimeout = 5   // seconds
	IdleTimeout      = 120 // seconds
)
