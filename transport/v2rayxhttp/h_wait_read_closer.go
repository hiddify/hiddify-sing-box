package xhttp

// closeWithError closes a stream that got no response body, such as one the server answered
// with a status other than 200. Read then returns err instead of io.ErrClosedPipe, so the log
// says why the connection failed.
func (w *WaitReadCloser) closeWithError(err error) {
	w.access.Lock()
	if !w.closed {
		w.err = err
	}
	w.access.Unlock()
	w.Close()
}
