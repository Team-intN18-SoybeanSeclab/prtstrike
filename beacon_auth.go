package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const beaconTimestampWindow = 300 * time.Second

var (
	// seenSignatures blocks exact replays inside the timestamp window.
	seenSignatures = make(map[string]struct{})
	seenSigMu      sync.Mutex
)

func credentialForBeacon(beaconID string, signed []byte, sig string) (key string, payloadID string, ok bool) {
	var cred BeaconCredential
	if err := db.First(&cred, "beacon_id = ?", beaconID).Error; err == nil {
		return cred.Key, cred.PayloadID, true
	}

	var payloads []Payload
	if err := db.Select("id", "beacon_key").Find(&payloads).Error; err != nil {
		return "", "", false
	}
	for _, p := range payloads {
		if p.BeaconKey == "" {
			continue
		}
		if verifyBeaconMAC(p.BeaconKey, signed, sig) {
			db.Create(&BeaconCredential{
				BeaconID:  beaconID,
				Key:       p.BeaconKey,
				PayloadID: p.ID,
				CreatedAt: time.Now(),
			})
			addLog("SEC", fmt.Sprintf("BEACON_KEY_BOUND: %s -> payload %s", beaconID, p.ID))
			return p.BeaconKey, p.ID, true
		}
	}
	return "", "", false
}

func verifyBeaconMAC(key string, signed []byte, sig string) bool {
	if key == "" || sig == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(signed)
	expected := mac.Sum(nil)
	given, err := hex.DecodeString(sig)
	if err != nil || len(given) != len(expected) {
		return false
	}
	return hmac.Equal(given, expected)
}

func computeBeaconMAC(key string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// replaySeen returns true if this signature was already accepted.
func replaySeen(sig string) bool {
	seenSigMu.Lock()
	defer seenSigMu.Unlock()
	if _, ok := seenSignatures[sig]; ok {
		return true
	}
	// Bound the cache; the timestamp window (±5min) keeps practical replay
	// traffic small, so FIFO eviction is sufficient.
	if len(seenSignatures) >= 8192 {
		for k := range seenSignatures {
			delete(seenSignatures, k)
			break
		}
	}
	seenSignatures[sig] = struct{}{}
	return false
}

// authBeaconRequest validates timestamp, replay and HMAC for an HTTP beacon
// request. Returns the beacon ID on success.
func authBeaconRequest(beaconID, sig, tsStr, nonce string, body []byte) (string, bool, string) {
	if beaconID == "" || sig == "" || nonce == "" {
		return beaconID, false, "MISSING_AUTH_HEADERS"
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return beaconID, false, "INVALID_TIMESTAMP"
	}
	if d := time.Since(time.Unix(ts, 0)); d > beaconTimestampWindow || d < -beaconTimestampWindow {
		return beaconID, false, "TIMESTAMP_OUT_OF_RANGE"
	}
	if replaySeen(sig + "@" + tsStr + "@" + nonce) {
		return beaconID, false, "REPLAYED_SIGNATURE"
	}
	signed := beaconSignedPayload(tsStr, nonce, body)
	key, _, ok := credentialForBeacon(beaconID, signed, sig)
	if !ok {
		return beaconID, false, "UNKNOWN_BEACON_OR_BAD_SIGNATURE"
	}
	if !verifyBeaconMAC(key, signed, sig) {
		return beaconID, false, "BAD_SIGNATURE"
	}
	return beaconID, true, ""
}

func beaconSignedPayload(tsStr, nonce string, body []byte) []byte {
	b := make([]byte, 0, len(tsStr)+1+len(nonce)+1+len(body))
	b = append(b, tsStr...)
	b = append(b, '.')
	b = append(b, nonce...)
	b = append(b, '.')
	b = append(b, body...)
	return b
}

// authTCPMsg validates a signed TCPMsg envelope using the given key.
func authTCPMsg(key string, msg *TCPMsg, raw []byte) bool {
	if key == "" || msg.Sig == "" || msg.TS == 0 || msg.Nonce == "" {
		return false
	}
	if d := time.Since(time.Unix(msg.TS, 0)); d > beaconTimestampWindow || d < -beaconTimestampWindow {
		return false
	}
	if replaySeen(msg.Sig + "@" + strconv.FormatInt(msg.TS, 10) + "@" + msg.Nonce) {
		return false
	}
	return verifyBeaconMAC(key, tcpSignString(msg.Type, msg.TS, msg.Nonce, raw), msg.Sig)
}

// tcpSignString produces the canonical signing string for a TCP message.
func tcpSignString(msgType string, ts int64, nonce string, data []byte) []byte {
	var b strings.Builder
	b.WriteString(msgType)
	b.WriteByte('.')
	b.WriteString(strconv.FormatInt(ts, 10))
	b.WriteByte('.')
	b.WriteString(nonce)
	b.WriteByte('.')
	b.Write(data)
	return []byte(b.String())
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

var (
	checkinBuckets = make(map[string]*tokenBucket)
	checkinRateMu  sync.Mutex
)

const (
	checkinBucketSize    = 240.0
	checkinRefillPerSec  = 8.0
	checkinBucketCleanup = 4096
)

func allowCheckin(ip string) bool {
	checkinRateMu.Lock()
	defer checkinRateMu.Unlock()

	now := time.Now()
	if len(checkinBuckets) > checkinBucketCleanup {
		for k, b := range checkinBuckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(checkinBuckets, k)
			}
		}
	}
	b, ok := checkinBuckets[ip]
	if !ok {
		b = &tokenBucket{tokens: checkinBucketSize, last: now}
		checkinBuckets[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * checkinRefillPerSec
	if b.tokens > checkinBucketSize {
		b.tokens = checkinBucketSize
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type loginState struct {
	fails       int
	lockedUntil time.Time
}

var (
	loginStates = make(map[string]*loginState)
	loginMu     sync.Mutex
)

const (
	loginMaxFails     = 5
	loginLockDuration = 15 * time.Minute
	loginStateMaxFill = 8192
)

// loginLocked reports whether the IP+username pair is currently locked out
// after repeated failures.
func loginLocked(key string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	if st, ok := loginStates[key]; ok {
		if time.Now().Before(st.lockedUntil) {
			return true
		}
	}
	return false
}

func loginRecordFailure(key string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	if len(loginStates) > loginStateMaxFill {
		for k, st := range loginStates {
			if time.Now().After(st.lockedUntil) {
				delete(loginStates, k)
			}
		}
	}
	st, ok := loginStates[key]
	if !ok {
		st = &loginState{}
		loginStates[key] = st
	}
	st.fails++
	if st.fails >= loginMaxFails {
		st.lockedUntil = time.Now().Add(loginLockDuration)
		st.fails = 0
	}
}

func loginRecordSuccess(key string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	delete(loginStates, key)
}

func loginKey(ip, username string) string {
	return net.JoinHostPort(ip, username)
}
