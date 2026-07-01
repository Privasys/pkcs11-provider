package main

import "sync"

// session holds per-session state. The find* fields back C_FindObjects (the
// snapshot of matching object handles and the cursor into it); sign* / the
// decrypt/wrap fields back the single-shot crypto-op state machines.
type session struct {
	// FindObjects cursor.
	findActive  bool
	findMatches []uint
	findPos     int

	// SignInit/Sign one-shot + SignUpdate/SignFinal streaming state.
	signKey  uint   // object handle of the active signing key (0 = none)
	signMech uint   // active CKM_*
	signBuf  []byte // accumulated message for the streaming (Update/Final) path

	// DecryptInit/Decrypt one-shot state (CKM_AES_GCM).
	decryptKey uint   // object handle of the active AES key (0 = none)
	decryptIV  []byte // GCM IV from the mechanism params
}

var (
	sessMu   sync.Mutex
	sessions = map[uint]*session{}
	nextSess uint = 1
)

func sessionOpen() uint {
	sessMu.Lock()
	defer sessMu.Unlock()
	h := nextSess
	nextSess++
	sessions[h] = &session{}
	return h
}

func sessionClose(h uint) bool {
	sessMu.Lock()
	defer sessMu.Unlock()
	if _, ok := sessions[h]; !ok {
		return false
	}
	delete(sessions, h)
	return true
}

func sessionValid(h uint) bool {
	sessMu.Lock()
	defer sessMu.Unlock()
	_, ok := sessions[h]
	return ok
}

// withSession runs fn under the session lock; ok=false if the handle is unknown.
func withSession(h uint, fn func(*session)) (ok bool) {
	sessMu.Lock()
	defer sessMu.Unlock()
	s, ok := sessions[h]
	if !ok {
		return false
	}
	fn(s)
	return true
}

func sessionsReset() {
	sessMu.Lock()
	defer sessMu.Unlock()
	sessions = map[uint]*session{}
	nextSess = 1
}
