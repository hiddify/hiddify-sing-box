package awg

import (
	"bytes"
	"testing"
)

func TestH_AwgReservedBytes(t *testing.T) {
	r := &Reserved{Bytes: [3]byte{124, 245, 25}, Types: [4]byte{1, 2, 3, 4}}
	initiation := append([]byte{1, 0, 0, 0}, make([]byte, 144)...)
	r.write(initiation)
	if !bytes.Equal(initiation[:4], []byte{1, 124, 245, 25}) {
		t.Fatalf("initiation header %v", initiation[:4])
	}
	for _, junk := range [][]byte{{0xc0, 0, 0, 0, 1}, {1, 7, 0, 0}, {9}} {
		before := bytes.Clone(junk)
		r.write(junk)
		if !bytes.Equal(junk, before) {
			t.Errorf("junk %v changed to %v", before, junk)
		}
	}
	response := []byte{2, 124, 245, 25, 9, 9}
	r.clear(response)
	if !bytes.Equal(response, []byte{2, 0, 0, 0, 9, 9}) {
		t.Errorf("response %v", response)
	}
	var none *Reserved
	none.write(initiation)
	none.clear(response)
}
