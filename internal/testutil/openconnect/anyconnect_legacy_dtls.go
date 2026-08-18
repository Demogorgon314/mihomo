package openconnect

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // Cisco DTLS 0.9 compatibility fixture.
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // Cisco DTLS 0.9 compatibility fixture.
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
)

const (
	fakeLegacyVersion           = 0x0100
	fakeLegacyCipherAES128SHA   = 0x002f
	fakeLegacyRecordHeaderSize  = 13
	fakeLegacyHandshakeSize     = 12
	fakeLegacyContentCCS        = 20
	fakeLegacyContentAlert      = 21
	fakeLegacyContentHandshake  = 22
	fakeLegacyContentData       = 23
	fakeLegacyClientHello       = 1
	fakeLegacyServerHello       = 2
	fakeLegacyHelloVerify       = 3
	fakeLegacyHandshakeFinished = 20
)

type fakeLegacyDTLSRecord struct {
	contentType byte
	epoch       uint16
	sequence    uint64
	payload     []byte
}

type fakeLegacyDTLSKeys struct {
	clientMAC []byte
	serverMAC []byte
	clientKey []byte
	serverKey []byte
}

type fakeLegacyReplayWindow struct {
	initialized bool
	maximum     uint64
	bitmap      uint64
}

func (w *fakeLegacyReplayWindow) accept(sequence uint64) bool {
	if !w.initialized {
		w.initialized = true
		w.maximum = sequence
		w.bitmap = 1
		return true
	}
	if sequence > w.maximum {
		shift := sequence - w.maximum
		if shift >= 64 {
			w.bitmap = 1
		} else {
			w.bitmap = w.bitmap<<shift | 1
		}
		w.maximum = sequence
		return true
	}
	difference := w.maximum - sequence
	if difference >= 64 {
		return false
	}
	mask := uint64(1) << difference
	if w.bitmap&mask != 0 {
		return false
	}
	w.bitmap |= mask
	return true
}

type fakeLegacyDTLSSession struct {
	remote             *net.UDPAddr
	masterSecret       []byte
	clientHelloBody    []byte
	serverHelloBody    []byte
	serverFinished     []byte
	keys               fakeLegacyDTLSKeys
	established        bool
	serverSequence     uint64
	clientReplay       fakeLegacyReplayWindow
	pendingReorderData []byte
}

func (s *fakeLegacyDTLSSession) destroy() {
	if s == nil {
		return
	}
	clear(s.masterSecret)
	clear(s.clientHelloBody)
	clear(s.serverHelloBody)
	clear(s.serverFinished)
	clear(s.keys.clientMAC)
	clear(s.keys.serverMAC)
	clear(s.keys.clientKey)
	clear(s.keys.serverKey)
	clear(s.pendingReorderData)
	*s = fakeLegacyDTLSSession{}
}

func (g *AnyConnectGateway) runLegacyDTLS() {
	defer g.waitGroup.Done()
	buffer := make([]byte, maximumDTLSPacketSize+512)
	for {
		length, remote, err := g.legacyDTLSConn.ReadFromUDP(buffer)
		if err != nil {
			if g.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				g.addError(fmt.Errorf("read fake legacy DTLS datagram: %w", err))
			}
			return
		}
		if g.dtlsBlackhole.Load() {
			continue
		}
		payload := append([]byte(nil), buffer[:length]...)
		if err := g.handleLegacyDTLSDatagram(remote, payload); err != nil {
			g.addError(err)
		}
	}
}

func (g *AnyConnectGateway) handleLegacyDTLSDatagram(remote *net.UDPAddr, datagram []byte) error {
	records, err := parseFakeLegacyRecords(datagram)
	if err != nil {
		return err
	}
	g.legacyLock.Lock()
	defer g.legacyLock.Unlock()
	for _, record := range records {
		if record.epoch == 0 && record.contentType == fakeLegacyContentHandshake {
			messageType, sequence, body, parseErr := parseFakeLegacyHandshake(record.payload)
			if parseErr != nil {
				return parseErr
			}
			if messageType != fakeLegacyClientHello || sequence != 0 {
				return errors.New("unexpected fake legacy DTLS handshake message")
			}
			clientRandom, sessionID, cookie, cipherSuite, parseErr := parseFakeLegacyClientHello(body)
			if parseErr != nil {
				return parseErr
			}
			if !bytes.Equal(sessionID, fakeDTLSSessionID()) || cipherSuite != fakeLegacyCipherAES128SHA {
				return errors.New("fake legacy DTLS client did not offer the negotiated session and cipher")
			}
			if len(cookie) == 0 {
				return g.sendLegacyHelloVerify(remote)
			}
			if !bytes.Equal(cookie, []byte("mihomo-legacy")) {
				return errors.New("fake legacy DTLS client returned an invalid cookie")
			}
			return g.sendLegacyServerFlight(remote, body, clientRandom)
		}
		if g.legacySession == nil || !sameUDPAddress(g.legacySession.remote, remote) {
			return errors.New("fake legacy DTLS received data without an owned session")
		}
		if !g.legacySession.established {
			if err := g.acceptLegacyClientFinished(record); err != nil {
				return err
			}
			continue
		}
		if record.contentType != fakeLegacyContentData || record.epoch != 1 {
			continue
		}
		plaintext, decryptErr := decryptFakeLegacyRecord(record, g.legacySession.keys.clientKey, g.legacySession.keys.clientMAC)
		if decryptErr != nil {
			return fmt.Errorf("decrypt fake legacy DTLS client data: %w", decryptErr)
		}
		if !g.legacySession.clientReplay.accept(record.sequence) {
			continue
		}
		if err := g.handleLegacyApplicationPacket(plaintext); err != nil {
			return err
		}
	}
	return nil
}

func (g *AnyConnectGateway) sendLegacyHelloVerify(remote *net.UDPAddr) error {
	body := append([]byte{1, 0, byte(len("mihomo-legacy"))}, []byte("mihomo-legacy")...)
	record, err := marshalFakeLegacyRecord(fakeLegacyDTLSRecord{
		contentType: fakeLegacyContentHandshake,
		sequence:    0,
		payload:     buildFakeLegacyHandshake(fakeLegacyHelloVerify, 0, body),
	})
	if err != nil {
		return err
	}
	return g.writeLegacyDatagram(remote, record)
}

func (g *AnyConnectGateway) sendLegacyServerFlight(remote *net.UDPAddr, clientHelloBody []byte, clientRandom []byte) error {
	g.pskLock.RLock()
	masterSecret := append([]byte(nil), g.dtlsMasterSecret...)
	g.pskLock.RUnlock()
	if len(masterSecret) != 48 {
		return errors.New("fake legacy DTLS master secret is not ready")
	}
	serverRandom := make([]byte, 32)
	if _, err := rand.Read(serverRandom); err != nil {
		return fmt.Errorf("generate fake legacy DTLS server random: %w", err)
	}
	serverHelloBody := make([]byte, 0, 72)
	serverHelloBody = append(serverHelloBody, 1, 0)
	serverHelloBody = append(serverHelloBody, serverRandom...)
	serverHelloBody = append(serverHelloBody, byte(len(fakeDTLSSessionID())))
	serverHelloBody = append(serverHelloBody, fakeDTLSSessionID()...)
	selectedCipher := uint16(fakeLegacyCipherAES128SHA)
	if g.scenario.LegacyDTLSFault == "unsupported-cipher" {
		selectedCipher = 0xdead
	}
	serverHelloBody = binary.BigEndian.AppendUint16(serverHelloBody, selectedCipher)
	serverHelloBody = append(serverHelloBody, 0)
	keys, err := deriveFakeLegacyKeys(masterSecret, clientRandom, serverRandom)
	if err != nil {
		return err
	}
	serverFinished, err := fakeLegacyFinished(masterSecret, "server finished", append(append([]byte(nil), clientHelloBody...), serverHelloBody...))
	if err != nil {
		return err
	}
	if g.scenario.LegacyDTLSFault == "bad-finished" {
		serverFinished[0] ^= 0xff
	}
	serverHello, err := marshalFakeLegacyRecord(fakeLegacyDTLSRecord{
		contentType: fakeLegacyContentHandshake,
		sequence:    1,
		payload:     buildFakeLegacyHandshake(fakeLegacyServerHello, 1, serverHelloBody),
	})
	if err != nil {
		return err
	}
	ccs, err := marshalFakeLegacyRecord(fakeLegacyDTLSRecord{contentType: fakeLegacyContentCCS, sequence: 2, payload: []byte{1, 0, 2}})
	if err != nil {
		return err
	}
	finished, err := encryptFakeLegacyRecord(fakeLegacyDTLSRecord{
		contentType: fakeLegacyContentHandshake,
		epoch:       1,
		sequence:    0,
		payload:     buildFakeLegacyHandshake(fakeLegacyHandshakeFinished, 3, serverFinished),
	}, keys.serverKey, keys.serverMAC)
	if err != nil {
		return err
	}
	if g.scenario.LegacyDTLSFault == "downgrade-version" {
		binary.BigEndian.PutUint16(serverHello[1:3], 0xfeff)
	}
	if g.legacySession != nil {
		g.legacySession.destroy()
	}
	g.legacySession = &fakeLegacyDTLSSession{
		remote:          cloneUDPAddress(remote),
		masterSecret:    masterSecret,
		clientHelloBody: append([]byte(nil), clientHelloBody...),
		serverHelloBody: serverHelloBody,
		serverFinished:  serverFinished,
		keys:            keys,
		serverSequence:  1,
	}
	flight := append(append(serverHello, ccs...), finished...)
	return g.writeLegacyDatagram(remote, flight)
}

func (g *AnyConnectGateway) acceptLegacyClientFinished(record fakeLegacyDTLSRecord) error {
	session := g.legacySession
	if record.contentType == fakeLegacyContentCCS {
		if record.epoch != 0 || !bytes.Equal(record.payload, []byte{1, 0, 2}) {
			return errors.New("invalid fake legacy DTLS client CCS")
		}
		return nil
	}
	if record.contentType != fakeLegacyContentHandshake || record.epoch != 1 {
		return nil
	}
	plaintext, err := decryptFakeLegacyRecord(record, session.keys.clientKey, session.keys.clientMAC)
	if err != nil {
		return fmt.Errorf("decrypt fake legacy DTLS client Finished: %w", err)
	}
	messageType, sequence, body, err := parseFakeLegacyHandshake(plaintext)
	if err != nil {
		return err
	}
	transcript := append(append(append([]byte(nil), session.clientHelloBody...), session.serverHelloBody...), session.serverFinished...)
	expected, err := fakeLegacyFinished(session.masterSecret, "client finished", transcript)
	if err != nil {
		return err
	}
	if messageType != fakeLegacyHandshakeFinished || sequence != 3 || subtle.ConstantTimeCompare(body, expected) != 1 {
		return errors.New("fake legacy DTLS client Finished verification failed")
	}
	session.established = true
	g.legacyHandshakeObserved.Store(true)
	g.record("legacy-dtls-handshake", "validated BAD_VER session resumption and CCS/Finished")
	return nil
}

func (g *AnyConnectGateway) LegacyDTLSHandshakeObserved() bool {
	return g != nil && g.legacyHandshakeObserved.Load()
}

func (g *AnyConnectGateway) LegacyDTLSOffered() bool {
	return g != nil && g.legacyDTLSOffered.Load()
}

func (g *AnyConnectGateway) handleLegacyApplicationPacket(packet []byte) error {
	if len(packet) == 0 {
		return errors.New("empty fake legacy DTLS application packet")
	}
	switch packet[0] {
	case cstpPacketData:
		g.record("legacy-dtls-data", "received legacy DTLS data packet")
		replies, err := handlePeerPackets(g.peer, packet[1:])
		if err != nil {
			return err
		}
		for _, reply := range replies {
			response := append([]byte{cstpPacketData}, reply...)
			if err := g.sendLegacyApplication(response); err != nil {
				return err
			}
		}
		return nil
	case cstpPacketDPDRequest:
		response := append([]byte(nil), packet...)
		response[0] = cstpPacketDPDResponse
		return g.sendLegacyApplication(response)
	case cstpPacketDPDResponse, cstpPacketKeepalive:
		return nil
	default:
		return fmt.Errorf("unexpected fake legacy DTLS packet type: %d", packet[0])
	}
}

func (g *AnyConnectGateway) sendLegacyApplication(payload []byte) error {
	session := g.legacySession
	record := fakeLegacyDTLSRecord{contentType: fakeLegacyContentData, epoch: 1, sequence: session.serverSequence, payload: payload}
	macKey := session.keys.serverMAC
	dataFault := len(payload) > 0 && payload[0] == cstpPacketData
	if dataFault && g.scenario.LegacyDTLSFault == "bad-data-mac" {
		macKey = append([]byte(nil), macKey...)
		macKey[0] ^= 0xff
	}
	encoded, err := encryptFakeLegacyRecord(record, session.keys.serverKey, macKey)
	if err != nil {
		return err
	}
	session.serverSequence++
	if !dataFault {
		return g.writeLegacyDatagram(session.remote, encoded)
	}
	switch g.scenario.LegacyDTLSFault {
	case "bad-padding":
		encoded[len(encoded)-1] ^= 0xff
	case "duplicate-data":
		if err := g.writeLegacyDatagram(session.remote, encoded); err != nil {
			return err
		}
		return g.writeLegacyDatagram(session.remote, encoded)
	case "reorder-data":
		if session.pendingReorderData == nil {
			session.pendingReorderData = encoded
			return nil
		}
		if err := g.writeLegacyDatagram(session.remote, encoded); err != nil {
			return err
		}
		pending := session.pendingReorderData
		session.pendingReorderData = nil
		return g.writeLegacyDatagram(session.remote, pending)
	}
	return g.writeLegacyDatagram(session.remote, encoded)
}

func (g *AnyConnectGateway) writeLegacyDatagram(remote *net.UDPAddr, payload []byte) error {
	count, err := g.legacyDTLSConn.WriteToUDP(payload, remote)
	if err != nil {
		return fmt.Errorf("write fake legacy DTLS datagram: %w", err)
	}
	if count != len(payload) {
		return fmt.Errorf("short fake legacy DTLS write: %d of %d", count, len(payload))
	}
	return nil
}

func parseFakeLegacyClientHello(body []byte) ([]byte, []byte, []byte, uint16, error) {
	if len(body) < 38 || binary.BigEndian.Uint16(body[:2]) != fakeLegacyVersion {
		return nil, nil, nil, 0, errors.New("invalid fake legacy DTLS ClientHello version")
	}
	clientRandom := append([]byte(nil), body[2:34]...)
	position := 34
	sessionLength := int(body[position])
	position++
	if len(body) < position+sessionLength+1 {
		return nil, nil, nil, 0, errors.New("truncated fake legacy DTLS ClientHello session")
	}
	sessionID := append([]byte(nil), body[position:position+sessionLength]...)
	position += sessionLength
	cookieLength := int(body[position])
	position++
	if len(body) < position+cookieLength+4 {
		return nil, nil, nil, 0, errors.New("truncated fake legacy DTLS ClientHello cookie")
	}
	cookie := append([]byte(nil), body[position:position+cookieLength]...)
	position += cookieLength
	cipherLength := int(binary.BigEndian.Uint16(body[position : position+2]))
	position += 2
	if cipherLength != 2 || len(body) < position+cipherLength {
		return nil, nil, nil, 0, errors.New("invalid fake legacy DTLS ClientHello cipher list")
	}
	return clientRandom, sessionID, cookie, binary.BigEndian.Uint16(body[position : position+2]), nil
}

func parseFakeLegacyRecords(datagram []byte) ([]fakeLegacyDTLSRecord, error) {
	var records []fakeLegacyDTLSRecord
	for len(datagram) > 0 {
		if len(datagram) < fakeLegacyRecordHeaderSize {
			return nil, errors.New("short fake legacy DTLS record")
		}
		if binary.BigEndian.Uint16(datagram[1:3]) != fakeLegacyVersion {
			return nil, errors.New("unexpected fake legacy DTLS record version")
		}
		length := int(binary.BigEndian.Uint16(datagram[11:13]))
		if len(datagram) < fakeLegacyRecordHeaderSize+length {
			return nil, errors.New("truncated fake legacy DTLS record")
		}
		records = append(records, fakeLegacyDTLSRecord{
			contentType: datagram[0],
			epoch:       binary.BigEndian.Uint16(datagram[3:5]),
			sequence:    readFakeUint48(datagram[5:11]),
			payload:     append([]byte(nil), datagram[13:13+length]...),
		})
		datagram = datagram[13+length:]
	}
	return records, nil
}

func marshalFakeLegacyRecord(record fakeLegacyDTLSRecord) ([]byte, error) {
	if record.sequence > 0x0000ffffffffffff || len(record.payload) > 65535 {
		return nil, errors.New("invalid fake legacy DTLS record size or sequence")
	}
	encoded := make([]byte, fakeLegacyRecordHeaderSize+len(record.payload))
	encoded[0] = record.contentType
	binary.BigEndian.PutUint16(encoded[1:3], fakeLegacyVersion)
	binary.BigEndian.PutUint16(encoded[3:5], record.epoch)
	putFakeUint48(encoded[5:11], record.sequence)
	binary.BigEndian.PutUint16(encoded[11:13], uint16(len(record.payload)))
	copy(encoded[13:], record.payload)
	return encoded, nil
}

func buildFakeLegacyHandshake(messageType byte, sequence uint16, body []byte) []byte {
	encoded := make([]byte, fakeLegacyHandshakeSize+len(body))
	encoded[0] = messageType
	putFakeUint24(encoded[1:4], len(body))
	binary.BigEndian.PutUint16(encoded[4:6], sequence)
	putFakeUint24(encoded[9:12], len(body))
	copy(encoded[12:], body)
	return encoded
}

func parseFakeLegacyHandshake(payload []byte) (byte, uint16, []byte, error) {
	if len(payload) < fakeLegacyHandshakeSize {
		return 0, 0, nil, errors.New("short fake legacy DTLS handshake")
	}
	length := readFakeUint24(payload[1:4])
	if readFakeUint24(payload[6:9]) != 0 || readFakeUint24(payload[9:12]) != length || len(payload) != 12+length {
		return 0, 0, nil, errors.New("fragmented fake legacy DTLS handshake")
	}
	return payload[0], binary.BigEndian.Uint16(payload[4:6]), append([]byte(nil), payload[12:]...), nil
}

func deriveFakeLegacyKeys(masterSecret []byte, clientRandom []byte, serverRandom []byte) (fakeLegacyDTLSKeys, error) {
	seed := append(append([]byte(nil), serverRandom...), clientRandom...)
	material, err := fakeTLS10PRF(masterSecret, "key expansion", seed, 104)
	if err != nil {
		return fakeLegacyDTLSKeys{}, err
	}
	return fakeLegacyDTLSKeys{
		clientMAC: append([]byte(nil), material[:20]...),
		serverMAC: append([]byte(nil), material[20:40]...),
		clientKey: append([]byte(nil), material[40:56]...),
		serverKey: append([]byte(nil), material[56:72]...),
	}, nil
}

func encryptFakeLegacyRecord(record fakeLegacyDTLSRecord, key []byte, macKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mac := fakeLegacyRecordMAC(record, record.payload, macKey)
	plaintext := append(append([]byte(nil), record.payload...), mac...)
	paddingLength := aes.BlockSize - len(plaintext)%aes.BlockSize
	for range paddingLength {
		plaintext = append(plaintext, byte(paddingLength-1))
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(plaintext, plaintext)
	record.payload = append(iv, plaintext...)
	return marshalFakeLegacyRecord(record)
}

func decryptFakeLegacyRecord(record fakeLegacyDTLSRecord, key []byte, macKey []byte) ([]byte, error) {
	if record.epoch != 1 || len(record.payload) < aes.BlockSize*3 || (len(record.payload)-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, errors.New("invalid fake legacy DTLS encrypted record")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := append([]byte(nil), record.payload[aes.BlockSize:]...)
	cipher.NewCBCDecrypter(block, record.payload[:aes.BlockSize]).CryptBlocks(plaintext, plaintext)
	paddingLength := int(plaintext[len(plaintext)-1]) + 1
	if paddingLength > len(plaintext)-sha1.Size {
		return nil, errors.New("invalid fake legacy DTLS padding")
	}
	for _, value := range plaintext[len(plaintext)-paddingLength:] {
		if value != byte(paddingLength-1) {
			return nil, errors.New("invalid fake legacy DTLS padding")
		}
	}
	payloadLength := len(plaintext) - paddingLength - sha1.Size
	payload := plaintext[:payloadLength]
	receivedMAC := plaintext[payloadLength : payloadLength+sha1.Size]
	record.payload = payload
	expectedMAC := fakeLegacyRecordMAC(record, payload, macKey)
	if subtle.ConstantTimeCompare(receivedMAC, expectedMAC) != 1 {
		return nil, errors.New("invalid fake legacy DTLS MAC")
	}
	return append([]byte(nil), payload...), nil
}

func fakeLegacyRecordMAC(record fakeLegacyDTLSRecord, payload []byte, key []byte) []byte {
	header := make([]byte, 13)
	binary.BigEndian.PutUint16(header[:2], record.epoch)
	putFakeUint48(header[2:8], record.sequence)
	header[8] = record.contentType
	binary.BigEndian.PutUint16(header[9:11], fakeLegacyVersion)
	binary.BigEndian.PutUint16(header[11:13], uint16(len(payload)))
	mac := hmac.New(sha1.New, key) //nolint:gosec // Cisco DTLS 0.9 fixture.
	_, _ = mac.Write(header)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func fakeLegacyFinished(masterSecret []byte, label string, transcript []byte) ([]byte, error) {
	md5Digest := md5.Sum(transcript)   //nolint:gosec // Cisco DTLS 0.9 fixture.
	sha1Digest := sha1.Sum(transcript) //nolint:gosec // Cisco DTLS 0.9 fixture.
	seed := append(append([]byte(nil), md5Digest[:]...), sha1Digest[:]...)
	return fakeTLS10PRF(masterSecret, label, seed, 12)
}

func fakeTLS10PRF(secret []byte, label string, seed []byte, length int) ([]byte, error) {
	labeledSeed := append([]byte(label), seed...)
	halfLength := (len(secret) + 1) / 2
	md5Output := fakePHash(secret[:halfLength], labeledSeed, length, md5.New)
	sha1Output := fakePHash(secret[len(secret)-halfLength:], labeledSeed, length, sha1.New)
	for index := range md5Output {
		md5Output[index] ^= sha1Output[index]
	}
	return md5Output, nil
}

func fakePHash(secret []byte, seed []byte, length int, newHash func() hash.Hash) []byte {
	result := make([]byte, 0, length)
	a := append([]byte(nil), seed...)
	for len(result) < length {
		mac := hmac.New(newHash, secret)
		_, _ = mac.Write(a)
		a = mac.Sum(nil)
		mac.Reset()
		_, _ = mac.Write(a)
		_, _ = mac.Write(seed)
		result = append(result, mac.Sum(nil)...)
	}
	return result[:length]
}

func sameUDPAddress(left *net.UDPAddr, right *net.UDPAddr) bool {
	return left != nil && right != nil && left.Port == right.Port && left.IP.Equal(right.IP)
}

func cloneUDPAddress(address *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func putFakeUint24(destination []byte, value int) {
	destination[0] = byte(value >> 16)
	destination[1] = byte(value >> 8)
	destination[2] = byte(value)
}

func readFakeUint24(source []byte) int {
	return int(source[0])<<16 | int(source[1])<<8 | int(source[2])
}

func putFakeUint48(destination []byte, value uint64) {
	destination[0] = byte(value >> 40)
	destination[1] = byte(value >> 32)
	destination[2] = byte(value >> 24)
	destination[3] = byte(value >> 16)
	destination[4] = byte(value >> 8)
	destination[5] = byte(value)
}

func readFakeUint48(source []byte) uint64 {
	return uint64(source[0])<<40 | uint64(source[1])<<32 | uint64(source[2])<<24 |
		uint64(source[3])<<16 | uint64(source[4])<<8 | uint64(source[5])
}
