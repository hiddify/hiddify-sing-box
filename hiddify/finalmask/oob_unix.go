//go:build unix

package finalmask

import "golang.org/x/sys/unix"

const oobSupported = true

// sendOOB sends b on the connected socket fd as TCP urgent data. unix.Send reports no byte count:
// no error means all of b was sent.
func sendOOB(fd uintptr, b []byte) (int, error) {
	if err := unix.Send(int(fd), b, unix.MSG_OOB); err != nil {
		return 0, err
	}
	return len(b), nil
}
