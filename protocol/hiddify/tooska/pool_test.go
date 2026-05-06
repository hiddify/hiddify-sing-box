package tooska

import (
	"testing"

	"github.com/sagernet/sing-box/protocol/hiddify/tooska/scanner"
)

func TestPoolHitClampsAtCeiling(t *testing.T) {
	p := newPool()
	for i := 0; i < 25; i++ {
		p.recordHit(scanner.Result{IP: "1.1.1.1", Port: 80, Protocol: scanner.ProtoSOCKS5})
	}
	if got := p.score("1.1.1.1", 80); got != scoreCap {
		t.Fatalf("want score=%d, got %d", scoreCap, got)
	}
}

func TestPoolMissClampsAtFloor(t *testing.T) {
	p := newPool()
	for i := 0; i < 25; i++ {
		p.recordMiss("1.1.1.1", 80)
	}
	if got := p.score("1.1.1.1", 80); got != scoreFloor {
		t.Fatalf("want score=%d, got %d", scoreFloor, got)
	}
}

func TestPoolNegativeScoreResetsOnHit(t *testing.T) {
	p := newPool()
	for i := 0; i < 5; i++ {
		p.recordMiss("1.1.1.1", 80)
	}
	if p.score("1.1.1.1", 80) != -5 {
		t.Fatalf("expected -5 after 5 misses, got %d", p.score("1.1.1.1", 80))
	}
	p.recordHit(scanner.Result{IP: "1.1.1.1", Port: 80, Protocol: scanner.ProtoSOCKS5})
	if got := p.score("1.1.1.1", 80); got != 1 {
		t.Fatalf("want score=1 after reset+hit, got %d", got)
	}
}

func TestPoolScoreUnknownIsZero(t *testing.T) {
	p := newPool()
	if got := p.score("9.9.9.9", 1234); got != 0 {
		t.Fatalf("unknown should default 0, got %d", got)
	}
}

func TestPoolWorkingExcludesNegative(t *testing.T) {
	p := newPool()
	p.recordHit(scanner.Result{IP: "1.1.1.1", Port: 80, Protocol: scanner.ProtoSOCKS5})
	p.recordMiss("2.2.2.2", 80)
	w := p.working(0)
	if len(w) != 1 || w[0].IP != "1.1.1.1" {
		t.Fatalf("want only 1.1.1.1 as working, got %+v", w)
	}
}

func TestPoolWorkingExcludesNoProtocol(t *testing.T) {
	p := newPool()
	p.recordMiss("3.3.3.3", 80)
	if got := p.workingCount(); got != 0 {
		t.Fatalf("want 0 working, got %d", got)
	}
	p.recordHit(scanner.Result{IP: "3.3.3.3", Port: 80, Protocol: scanner.ProtoHTTP})
	if got := p.workingCount(); got != 1 {
		t.Fatalf("want 1 working after hit, got %d", got)
	}
}

func TestPoolWorkingOrderedByScoreThenLatency(t *testing.T) {
	p := newPool()
	p.recordHit(scanner.Result{IP: "1.1.1.1", Port: 80, Protocol: scanner.ProtoSOCKS5, LatencyMS: 200})
	p.recordHit(scanner.Result{IP: "2.2.2.2", Port: 80, Protocol: scanner.ProtoSOCKS5, LatencyMS: 50})
	p.recordHit(scanner.Result{IP: "2.2.2.2", Port: 80, Protocol: scanner.ProtoSOCKS5, LatencyMS: 50})
	w := p.working(0)
	if len(w) != 2 {
		t.Fatalf("want 2 working, got %d", len(w))
	}
	if w[0].IP != "2.2.2.2" {
		t.Fatalf("higher score first; got %s", w[0].IP)
	}
}

func TestPoolWorkingLimitTruncates(t *testing.T) {
	p := newPool()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		p.recordHit(scanner.Result{IP: ip, Port: 80, Protocol: scanner.ProtoSOCKS5})
	}
	if got := p.working(2); len(got) != 2 {
		t.Fatalf("want 2 with limit, got %d", len(got))
	}
}

func TestScanGateMutualExclusion(t *testing.T) {
	var g scanGate
	if !g.tryAcquire() {
		t.Fatal("first acquire should succeed")
	}
	if g.tryAcquire() {
		t.Fatal("second acquire while held must fail")
	}
	if !g.busy() {
		t.Fatal("busy() should report true while held")
	}
	g.release()
	if g.busy() {
		t.Fatal("busy() should report false after release")
	}
	if !g.tryAcquire() {
		t.Fatal("re-acquire after release should succeed")
	}
}
