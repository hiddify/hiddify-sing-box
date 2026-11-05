package monitoring

import "slices"

// cycleOrder orders the cycle's targets: the ones that answered, fastest first by their last
// delay, with the members never tested (delay 0) taking every other place among them, then the
// ones that failed, in this run or the last one. With 10, 12 and 15 ms, a failed one and four untested: 10, new, 12, new, 15,
// new, new, failed. The fastest of the last run are tested first, and a large subscription's new
// members do not wait for all of them, nor for a cycle of timeouts. delays is each target's last
// delay, cached or of this run.
func cycleOrder(tags []string, delays map[string]uint16) []string {
	var answered, untested, failed []string
	for _, tag := range tags {
		switch delay := delays[tag]; {
		case delay == 0:
			untested = append(untested, tag)
		case delay >= TimeoutDelay:
			failed = append(failed, tag)
		default:
			answered = append(answered, tag)
		}
	}
	slices.SortStableFunc(answered, func(a, b string) int {
		return int(delays[a]) - int(delays[b])
	})
	ordered := make([]string, 0, len(tags))
	for i := range max(len(answered), len(untested)) {
		if i < len(answered) {
			ordered = append(ordered, answered[i])
		}
		if i < len(untested) {
			ordered = append(ordered, untested[i])
		}
	}
	return append(ordered, failed...)
}
