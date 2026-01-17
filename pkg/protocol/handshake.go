package protocol

import (
	"bytes"
	"errors"
	"w33d-tunnel/pkg/crypto"
)

// Handshake Message Structure (Logical, not wire)
// Initiation: [HMAC 16] [E_C 32] [Encrypted: Version, Timestamp, Padding]
// Response: [Encrypted: E_S 32, Auth, Padding] [Tag 16]

const (
	LabelHandshakeKey     = "HandshakeKey"
	LabelHandshakeRespKey = "HandshakeResponseKey"
	LabelMasterSecret     = "SCR-UDP master"
	LabelSessionKeys      = "SCR-UDP key schedule"
)

// CreateHandshakeInitiation creates the client's initial packet.
func (s *Session) CreateHandshakeInitiation() ([]byte, error) {
	// 1. Generate Ephemeral Key E_C
	if err := s.GenerateEphemeralKeys(); err != nil {
		return nil, err
	}

	// 2. Compute Shared Secret SS = DH(E_C, PeerStatic)
	ss, err := crypto.ComputeSharedSecret(s.EphemeralPriv, s.PeerStaticPub)
	if err != nil {
		return nil, err
	}

	// 3. Derive Handshake Key HK
	hk, err := crypto.DeriveKeys(ss, nil, LabelHandshakeKey, KeySize)
	if err != nil {
		return nil, err
	}

	// 4. Prepare Payload
	// [Version 1b] [Timestamp 8b] [TokenLen 1b] [Token var] [Padding var]
	tokenBytes := []byte(s.Token)
	tokenLen := len(tokenBytes)
	if tokenLen > 255 {
		return nil, errors.New("token too long")
	}
	
	payload := make([]byte, 1+8+1+tokenLen+32) 
	payload[0] = 1 // Version
	// Timestamp...
	copy(payload[1:], crypto.RandomBytes(8))
	payload[9] = byte(tokenLen)
	copy(payload[10:], tokenBytes)
	copy(payload[10+tokenLen:], crypto.RandomBytes(32))

	// 5. Encrypt Payload
	// Nonce for handshake is 0 or random?
	// "nonce = 0 for this first message" (RFC Para 61)
	nonce := make([]byte, NonceSize) // Zero nonce

	encryptedPayload, err := crypto.Encrypt(hk, nonce, payload, nil)
	if err != nil {
		return nil, err
	}

	// 6. Construct Packet
	// [HMAC 16] [E_C 32] [EncryptedPayload]
	// HMAC is optional, RFC says "If a pre-shared secret...".
	// If not, it can be random or omitted.
	// RFC Para 59: "omitted or set to a random value".
	// Let's use random 16 bytes for now to look uniform.
	hmacVal := crypto.RandomBytes(16)

	var packet bytes.Buffer
	packet.Write(hmacVal)
	packet.Write(s.EphemeralPub)
	packet.Write(encryptedPayload)

	return packet.Bytes(), nil
}

// ProcessHandshakeResponse processes the server's response.
func (s *Session) ProcessHandshakeResponse(data []byte) error {
	// Data: [EncryptedPayload] [Tag 16]
	// Actually AEAD produces [Ciphertext + Tag].
	// So data is just the AEAD output.

	// 1. Re-compute Handshake Keys
	// We need SS = DH(E_C_priv, PeerStatic)
	ss, err := crypto.ComputeSharedSecret(s.EphemeralPriv, s.PeerStaticPub)
	if err != nil {
		return err
	}

	// Derive Response Key HK_res
	hkRes, err := crypto.DeriveKeys(ss, nil, LabelHandshakeRespKey, KeySize)
	if err != nil {
		return err
	}

	// 2. Decrypt
	// Nonce? "constant (0) or a counter (1)" (RFC Para 81)
	// Let's assume 0 for simplicity or 1 if distinct.
	// Since keys are different (Init vs Resp labels), 0 is safe.
	nonce := make([]byte, NonceSize)

	plaintext, err := crypto.Decrypt(hkRes, nonce, data, nil)
	if err != nil {
		return errors.New("failed to decrypt handshake response")
	}

	// 3. Extract E_S
	// Payload: [E_S 32] [Auth...]
	if len(plaintext) < 32 {
		return errors.New("response too short")
	}
	s.PeerEphemeralPub = plaintext[:32]

	// 4. Compute Ephemeral Shared Secret ES = DH(E_C, E_S)
	es, err := crypto.ComputeSharedSecret(s.EphemeralPriv, s.PeerEphemeralPub)
	if err != nil {
		return err
	}

	// 5. Derive Master Secret and Session Keys
	// master = HKDF(SS || ES, ...)
	combinedSecret := append(ss, es...)
	masterSecret, err := crypto.DeriveKeys(combinedSecret, nil, LabelMasterSecret, KeySize)
	if err != nil {
		return err
	}

	// Expand Session Keys
	// K_c2s (32), K_s2c (32), Salt (12), Salt (12), HK_c2s (32), HK_s2c (32)
	// Total: 32+32+12+12+32+32 = 152
	keyMat, err := crypto.DeriveKeys(masterSecret, nil, LabelSessionKeys, 152)
	if err != nil {
		return err
	}

	s.SendKey = keyMat[0:32]
	s.RecvKey = keyMat[32:64]
	s.SendNonceSalt = keyMat[64:76]
	s.RecvNonceSalt = keyMat[76:88]
	s.SendHeaderKey = keyMat[88:120]
	s.RecvHeaderKey = keyMat[120:152]

	// Note: Role Swap?
	// If I am Client, SendKey is K_c2s.
	// If I am Server, SendKey should be K_s2c.
	// The derivation order is fixed.
	// Let's assume K1=ClientSend, K2=ServerSend.
	if s.Role == RoleServer {
		s.SendKey, s.RecvKey = s.RecvKey, s.SendKey
		s.SendNonceSalt, s.RecvNonceSalt = s.RecvNonceSalt, s.SendNonceSalt
		s.SendHeaderKey, s.RecvHeaderKey = s.RecvHeaderKey, s.SendHeaderKey
	}

	s.State = StateEstablished
	return nil
}

// ProcessHandshakeInitiation (Server side)
func (s *Session) ProcessHandshakeInitiation(data []byte) ([]byte, error) {
	// Data: [HMAC 16] [E_C 32] [EncryptedPayload...]
	if len(data) < 16+32+16 { // Min size check
		return nil, errors.New("initiation too short")
	}

	// 1. Extract E_C
	peerEphemeralPub := data[16:48]
	s.PeerEphemeralPub = peerEphemeralPub

	// 2. Compute SS = DH(LocalStatic, E_C)
	ss, err := crypto.ComputeSharedSecret(s.LocalStaticPriv, peerEphemeralPub)
	if err != nil {
		return nil, err
	}

	// 3. Derive Handshake Key HK
	hk, err := crypto.DeriveKeys(ss, nil, LabelHandshakeKey, KeySize)
	if err != nil {
		return nil, err
	}

	// 4. Decrypt Payload
	encryptedPayload := data[48:]
	nonce := make([]byte, NonceSize)
	decrypted, err := crypto.Decrypt(hk, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt initiation")
	}
	
	// Parse Payload: [Version 1b] [Timestamp 8b] [TokenLen 1b] [Token var] [Padding...]
	if len(decrypted) < 10 {
		return nil, errors.New("payload too short")
	}
	
	// version := decrypted[0]
	tokenLen := int(decrypted[9])
	if len(decrypted) < 10+tokenLen {
		return nil, errors.New("payload too short for token")
	}
	
	s.Token = string(decrypted[10 : 10+tokenLen])
	// TODO: Validate Token here or later?
	// For now, we just store it in Session.

	// 5. Generate Server Ephemeral E_S
	if err := s.GenerateEphemeralKeys(); err != nil {
		return nil, err
	}

	// 6. Compute ES = DH(E_S, E_C)
	es, err := crypto.ComputeSharedSecret(s.EphemeralPriv, s.PeerEphemeralPub)
	if err != nil {
		return nil, err
	}

	// 7. Prepare Response Payload
	// [E_S 32] [Padding]
	payload := make([]byte, 32+32)
	copy(payload, s.EphemeralPub)
	copy(payload[32:], crypto.RandomBytes(32)) // Padding

	// 8. Encrypt Response
	// HK_res
	hkRes, err := crypto.DeriveKeys(ss, nil, LabelHandshakeRespKey, KeySize)
	if err != nil {
		return nil, err
	}

	encryptedResp, err := crypto.Encrypt(hkRes, nonce, payload, nil)
	if err != nil {
		return nil, err
	}

	// 9. Derive Session Keys
	combinedSecret := append(ss, es...)
	masterSecret, err := crypto.DeriveKeys(combinedSecret, nil, LabelMasterSecret, KeySize)
	if err != nil {
		return nil, err
	}

	keyMat, err := crypto.DeriveKeys(masterSecret, nil, LabelSessionKeys, 152)
	if err != nil {
		return nil, err
	}

	// Assign keys (Client=K1, Server=K2)
	// I am Server.
	s.RecvKey = keyMat[0:32]
	s.SendKey = keyMat[32:64]
	s.RecvNonceSalt = keyMat[64:76]
	s.SendNonceSalt = keyMat[76:88]
	s.RecvHeaderKey = keyMat[88:120]
	s.SendHeaderKey = keyMat[120:152]

	s.State = StateEstablished

	return encryptedResp, nil
}
