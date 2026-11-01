//go:build with_naive_outbound && darwin && !ios && !with_purego

package naive

// Chromium's base::mac::OuterBundleCachedInfoPlistData() (info_plist_data.o in the macOS
// libcronet.a) references _kCFBundleNumericVersionKey, which App Review rejects as a
// non-public API. Only multi-process code (Mach port rendezvous, child code signature checks)
// calls it, and Cronet runs in-process, so defining it here keeps the linker from pulling
// info_plist_data.o out of the archive. It returns an empty std::vector<uint8_t>: three null
// pointers, written through the indirect result register like the C++ original.

/*
typedef struct {
	void *begin;
	void *end;
	void *cap;
} hiddify_empty_vector;

__attribute__((visibility("hidden")))
hiddify_empty_vector hiddify_outer_bundle_cached_info_plist_data(void) __asm__("__ZN4base3mac30OuterBundleCachedInfoPlistDataEv");

hiddify_empty_vector hiddify_outer_bundle_cached_info_plist_data(void) {
	hiddify_empty_vector v = {0, 0, 0};
	return v;
}
*/
import "C"
