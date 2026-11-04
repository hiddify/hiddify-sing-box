package monitoring

import (
	"fmt"
)

// Worked reports a URL test result that worked: measured, in this run, and not a timeout. The
// groups and monitoring agree on it through here.
func Worked(delay uint16, fromCache bool) bool {
	return !fromCache && delay != 0 && delay < TimeoutDelay
}

// DelayString is a result for the MONITORING and LOWEST logs: "17 ms", "cached 17 ms", "failed",
// "untested".
func DelayString(delay uint16, fromCache bool) string {
	switch {
	case delay == 0:
		return "untested"
	case delay >= TimeoutDelay:
		return "failed"
	case fromCache:
		return fmt.Sprint("cached ", delay, " ms")
	default:
		return fmt.Sprint(delay, " ms")
	}
}

// testKind says, for the MONITORING log, how a test runs and what was known of the outbound
// before it.
func testKind(task *testTask, delay uint16, fromCache bool) string {
	kind := "regular"
	if task.staged {
		kind = "staged"
	}
	return fmt.Sprint(" (", kind, ", before: ", DelayString(delay, fromCache), ")")
}
