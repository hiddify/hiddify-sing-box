package dnstt

import (
	"bytes"
	"net"
)

type LoggingConn struct {
	net.Conn
	rx           bytes.Buffer
	tx           bytes.Buffer
	outbound     *Outbound
	tunnel_index int
}

func (c *LoggingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.rx.Write(b[:n])
	}
	return n, err
}

func (c *LoggingConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		c.tx.Write(b)
	}
	return c.Conn.Write(b)
}

func (c *LoggingConn) Close() error {
	c.outbound.logger.Info(c.outbound.Tag(), " Tunnel ", c.tunnel_index, " closing connection. TX bytes: ", c.tx.Len(), ", RX bytes: ", c.rx.Len())
	// bs := c.rx.Bytes()

	// fmt.Printf("TX bytes: \n%s\n", c.tx.String())
	// if len(bs) > 0 {
	// 	fmt.Printf("RX bytes: \n%s\n", c.tx.String())
	// } else {
	// 	fmt.Printf("RX bytes: %d \n", len(bs))
	// }
	return c.Conn.Close()
}
