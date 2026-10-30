package option

import "testing"

func TestH_AwgReservedMessageTypes(t *testing.T) {
	types, err := (&AwgOptions{Jc: 4, H1: "5", H2: "6"}).ReservedMessageTypes()
	if err != nil || types != [4]byte{5, 6, 3, 4} {
		t.Fatalf("types %v, err %v", types, err)
	}
	for name, awg := range map[string]AwgOptions{
		"s1":    {S1: 15},
		"range": {H1: "5-9"},
		"big":   {H1: "1111111"},
		"hpk":   {HeaderProtectionKey: "00"},
	} {
		if _, err := awg.ReservedMessageTypes(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
