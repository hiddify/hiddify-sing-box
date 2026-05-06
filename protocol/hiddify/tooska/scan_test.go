package tooska

import (
	"strings"
	"testing"
)

func TestParseCandidatesBareIP(t *testing.T) {
	got, err := parseCandidates([]string{"1.2.3.4"}, []int{1080, 8080})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(got))
	}
	if got[0].IP.String() != "1.2.3.4" || got[1].IP.String() != "1.2.3.4" {
		t.Fatalf("ip mismatch: %#v", got)
	}
	ports := map[int]bool{got[0].Port: true, got[1].Port: true}
	if !ports[1080] || !ports[8080] {
		t.Fatalf("ports mismatch: %#v", got)
	}
}

func TestParseCandidatesIPPortPin(t *testing.T) {
	got, err := parseCandidates([]string{"1.2.3.4:9999"}, []int{1080, 8080})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 candidate, got %d", len(got))
	}
	if got[0].Port != 9999 {
		t.Fatalf("want port 9999, got %d", got[0].Port)
	}
}

func TestParseCandidatesCIDRExpansion(t *testing.T) {
	got, err := parseCandidates([]string{"10.0.0.0/30"}, []int{1080})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 candidates, got %d", len(got))
	}
}

func TestParseCandidatesDedup(t *testing.T) {
	got, err := parseCandidates(
		[]string{"1.2.3.4", "1.2.3.4:1080", "1.2.3.4"},
		[]int{1080},
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 deduped candidate, got %d", len(got))
	}
}

func TestParseCandidatesIPv6Bracketed(t *testing.T) {
	got, err := parseCandidates([]string{"[::1]:1080"}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 || got[0].Port != 1080 {
		t.Fatalf("ipv6 parse failed: %#v", got)
	}
	if got[0].IP.String() != "::1" {
		t.Fatalf("ipv6 addr mismatch: %s", got[0].IP)
	}
}

func TestParseCandidatesIPv6Bare(t *testing.T) {
	got, err := parseCandidates([]string{"::1"}, []int{1080})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
}

func TestParseCandidatesDefaultPorts(t *testing.T) {
	got, err := parseCandidates([]string{"1.2.3.4"}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != len(defaultPorts) {
		t.Fatalf("want %d default ports, got %d", len(defaultPorts), len(got))
	}
}

func TestParseCandidatesEmptyTargets(t *testing.T) {
	if _, err := parseCandidates(nil, []int{1080}); err == nil {
		t.Fatal("want error for empty targets")
	}
}

func TestParseCandidatesInvalidIP(t *testing.T) {
	if _, err := parseCandidates([]string{"not-an-ip"}, []int{1080}); err == nil {
		t.Fatal("want error for invalid ip")
	}
}

func TestParseCandidatesInvalidCIDR(t *testing.T) {
	if _, err := parseCandidates([]string{"10.0.0.0/77"}, []int{1080}); err == nil {
		t.Fatal("want error for invalid cidr")
	}
}

func TestParseCandidatesPortOutOfRange(t *testing.T) {
	if _, err := parseCandidates([]string{"1.2.3.4:0"}, nil); err == nil {
		t.Fatal("want error for port=0")
	}
	if _, err := parseCandidates([]string{"1.2.3.4:99999"}, nil); err == nil {
		t.Fatal("want error for port=99999")
	}
}

func TestParseCandidatesCapEnforced(t *testing.T) {
	if _, err := parseCandidates([]string{"10.0.0.0/16"}, nil); err != nil {
		t.Fatalf("unexpected err for /16: %v", err)
	}
	_, err := parseCandidates([]string{"10.0.0.0/8"}, nil)
	if err == nil {
		t.Fatal("want cap error for /8 sweep")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want cap error message, got %v", err)
	}
}

func TestParseCandidatesTrimsAndSkipsEmpty(t *testing.T) {
	got, err := parseCandidates([]string{"  1.2.3.4  ", "", "   "}, []int{1080})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
}

func TestJoinHostPortIPv4(t *testing.T) {
	if got := joinHostPort("1.2.3.4", 80); got != "1.2.3.4:80" {
		t.Fatalf("ipv4 join: got %q", got)
	}
}

func TestJoinHostPortIPv6(t *testing.T) {
	if got := joinHostPort("::1", 80); got != "[::1]:80" {
		t.Fatalf("ipv6 join: got %q", got)
	}
}
