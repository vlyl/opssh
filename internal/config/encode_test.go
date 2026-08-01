package config

import (
	"strings"
	"testing"
)

func TestEncodeRoundTrip(t *testing.T) {
	t.Parallel()

	configuration, err := Parse(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(configuration)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := Parse(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatalf("Parse(encoded) error = %v\n%s", err, encoded)
	}
	if len(roundTrip.Hosts) != 1 || len(roundTrip.Tunnels) != 1 {
		t.Fatalf("round trip lost entries: %#v", roundTrip)
	}
	if !strings.Contains(string(encoded), "identities_only: true") {
		t.Fatalf("encoded configuration weakened identity selection:\n%s", encoded)
	}
}
