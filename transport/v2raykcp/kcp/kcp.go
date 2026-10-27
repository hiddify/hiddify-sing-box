// Package kcp - A Fast and Reliable ARQ Protocol
//
// Acknowledgement:
//
//	skywind3000@github for inventing the KCP protocol
//	xtaci@github for translating to Golang
//
// Hiddify: Xray's mKCP (github.com/xtls/xray-core/transport/internet/kcp, v26.10), under the
// Mozilla Public License 2.0 like the rest of Xray. Kept here to fix a data race in the
// receiving worker; the dialer, listener and protobuf config are replaced by sing-box's.
package kcp

const ProtocolName = "mkcp"
