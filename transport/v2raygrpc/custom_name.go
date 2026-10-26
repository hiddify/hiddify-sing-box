package v2raygrpc

import (
	"context"

	"google.golang.org/grpc"
)

type GunService interface {
	Context() context.Context
	Send(*Hunk) error
	Recv() (*Hunk, error)
}

func ServerDesc(name string, streamName string) grpc.ServiceDesc { //H: Xray's custom paths name the stream too
	return grpc.ServiceDesc{
		ServiceName: name,
		HandlerType: (*GunServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    streamName, //H
				Handler:       _GunService_Tun_Handler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "gun.proto",
	}
}

func (c *gunServiceClient) TunCustomName(ctx context.Context, name string, streamName string, opts ...grpc.CallOption) (GunService_TunClient, error) { //H
	stream, err := c.cc.NewStream(ctx, &ServerDesc(name, streamName).Streams[0], "/"+name+"/"+streamName, opts...) //H
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Hunk, Hunk]{ClientStream: stream}
	return x, nil
}

var _ GunServiceCustomNameClient = (*gunServiceClient)(nil)

type GunServiceCustomNameClient interface {
	TunCustomName(ctx context.Context, name string, streamName string, opts ...grpc.CallOption) (GunService_TunClient, error) //H
	Tun(ctx context.Context, opts ...grpc.CallOption) (GunService_TunClient, error)
}

func RegisterGunServiceCustomNameServer(s *grpc.Server, srv GunServiceServer, name string, streamName string) { //H
	desc := ServerDesc(name, streamName) //H
	s.RegisterService(&desc, srv)
}
