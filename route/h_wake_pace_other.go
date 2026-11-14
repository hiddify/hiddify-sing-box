//go:build !unix

package route

// datagramRead is not used here: a plain read is the connection's own.
type datagramRead struct{}

func (c *trackedConn) readDatagram(b []byte) (int, error) {
	return c.Conn.Read(b)
}
