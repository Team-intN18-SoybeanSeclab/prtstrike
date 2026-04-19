package main

// xorStr XOR-encodes/decodes a string with a key derived from its length.
// Used to deobfuscate sensitive strings at runtime.
func xorStr(s string, key byte) string {
	b := []byte(s)
	for i := range b {
		b[i] ^= key ^ byte(i&0x1F)
	}
	return string(b)
}

// obfuscatedUserAgent returns a User-Agent string built at runtime
// to avoid static string signatures in the binary.
func obfuscatedUserAgent() string {
	// Build Mozilla UA piece by piece to avoid single-string signature
	parts := [...]string{
		"Mo", "zil", "la/", "5.0",
		" (Wi", "ndo", "ws N", "T 1", "0.0",
		"; Wi", "n64", "; x", "64)",
		" Ap", "ple", "Web", "Kit",
		"/53", "7.3", "6",
	}
	var ua string
	for _, p := range parts {
		ua += p
	}
	return ua
}

// scrambleMemory overwrites a byte slice with random-looking data.
// Call this after you're done with sensitive data (keys, URLs, etc.)
func scrambleMemory(b []byte) {
	for i := range b {
		b[i] = byte(i*0x5A + 0x3C)
	}
}
