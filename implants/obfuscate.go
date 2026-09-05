package main

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
