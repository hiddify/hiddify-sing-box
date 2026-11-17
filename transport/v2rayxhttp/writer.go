package xhttp

import (
	common "github.com/sagernet/sing-box/common/xray"
	"github.com/sagernet/sing-box/common/xray/buf"
	"github.com/sagernet/sing-box/common/xray/pipe"
)

// A wrapper around pipe that ensures the size limit is exactly honored.
//
// The MultiBuffer pipe accepts any single WriteMultiBuffer call even if that
// single MultiBuffer exceeds the size limit, and then starts blocking on the
// next WriteMultiBuffer call. This means that ReadMultiBuffer can return more
// bytes than the size limit. We work around this by splitting a potentially
// too large write up into multiple.
type uploadWriter struct {
	*pipe.Writer
	maxLen int32
}

func (w uploadWriter) Write(b []byte) (int, error) {
	/*
		capacity := int(w.maxLen - w.Len())
		if capacity > 0 && capacity < len(b) {
			b = b[:capacity]
		}
	*/

	buffer := buf.MultiBufferContainer{}
	if piece := int(hUploadPiece(w.maxLen)); piece < buf.Size { //H: posts smaller than one buffer: pieces of the post size
		for rest := b; len(rest) > 0; rest = rest[min(len(rest), piece):] { //H
			one := buf.New()                                      //H
			common.Must2(one.Write(rest[:min(len(rest), piece)])) //H
			buffer.MultiBuffer = append(buffer.MultiBuffer, one)  //H
		} //H
	} else { //H
		common.Must2(buffer.Write(b))
	} //H

	var writed int
	for _, buff := range buffer.MultiBuffer {
		// the length is taken first: once written, the buffer belongs to the reader
		length := int(buff.Len())
		err := w.WriteMultiBuffer(buf.MultiBuffer{buff})
		if err != nil {
			return writed, err
		}
		writed += length
	}
	return writed, nil
}
