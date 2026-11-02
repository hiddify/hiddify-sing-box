//go:build windows

package finalmask

import "golang.org/x/sys/windows"

const oobSupported = true

// sendOOB sends b on the connected socket fd as TCP urgent data.
func sendOOB(fd uintptr, b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	buf := windows.WSABuf{Len: uint32(len(b)), Buf: &b[0]}
	var sent uint32
	err := windows.WSASend(windows.Handle(fd), &buf, 1, &sent, windows.MSG_OOB, nil, nil)
	return int(sent), err
}
