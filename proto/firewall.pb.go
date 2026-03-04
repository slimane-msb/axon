// Code generated from firewall.proto — hand-written stubs for build compatibility.
// In production, regenerate with: protoc --go_out=. --go-grpc_out=. proto/firewall.proto
package proto

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ─────────────────────────────────────────────
// Message types (matching firewall.proto)
// ─────────────────────────────────────────────

type FirewallLog struct {
	Timestamp string `protobuf:"bytes,1,opt,name=timestamp"`
	Interface string `protobuf:"bytes,2,opt,name=interface"`
	SrcIp     string `protobuf:"bytes,3,opt,name=src_ip"`
	DstIp     string `protobuf:"bytes,4,opt,name=dst_ip"`
	Fqdn      string `protobuf:"bytes,5,opt,name=fqdn"`
	RuleType  string `protobuf:"bytes,6,opt,name=rule_type"`
	Action    string `protobuf:"bytes,7,opt,name=action"`
	SrcPort   uint32 `protobuf:"varint,8,opt,name=src_port"`
	DstPort   uint32 `protobuf:"varint,9,opt,name=dst_port"`
	Protocol  string `protobuf:"bytes,10,opt,name=protocol"`
	Layer     string `protobuf:"bytes,11,opt,name=layer"`
}

func (x *FirewallLog) Reset()         {}
func (x *FirewallLog) String() string { return x.Fqdn }
func (x *FirewallLog) ProtoMessage()  {}

type RuleRequest struct {
	Target    string `protobuf:"bytes,1,opt,name=target"`
	Interface string `protobuf:"bytes,2,opt,name=interface"`
	RuleType  string `protobuf:"bytes,3,opt,name=rule_type"`
}

func (x *RuleRequest) Reset()         {}
func (x *RuleRequest) String() string { return x.Target }
func (x *RuleRequest) ProtoMessage()  {}

type RuleResponse struct {
	Success bool   `protobuf:"varint,1,opt,name=success"`
	Message string `protobuf:"bytes,2,opt,name=message"`
}

func (x *RuleResponse) Reset()         {}
func (x *RuleResponse) String() string { return x.Message }
func (x *RuleResponse) ProtoMessage()  {}

type ListRequest struct {
	Interface string `protobuf:"bytes,1,opt,name=interface"`
}

func (x *ListRequest) Reset()         {}
func (x *ListRequest) String() string { return x.Interface }
func (x *ListRequest) ProtoMessage()  {}

type ListResponse struct {
	Rules []*Rule `protobuf:"bytes,1,rep,name=rules"`
}

func (x *ListResponse) Reset()         {}
func (x *ListResponse) String() string { return "" }
func (x *ListResponse) ProtoMessage()  {}

type Rule struct {
	Target      string   `protobuf:"bytes,1,opt,name=target"`
	Interface   string   `protobuf:"bytes,2,opt,name=interface"`
	RuleType    string   `protobuf:"bytes,3,opt,name=rule_type"`
	EntryType   string   `protobuf:"bytes,4,opt,name=entry_type"`
	ResolvedIps []string `protobuf:"bytes,5,rep,name=resolved_ips"`
	TtlSeconds  int64    `protobuf:"varint,6,opt,name=ttl_seconds"`
}

func (x *Rule) Reset()         {}
func (x *Rule) String() string { return x.Target }
func (x *Rule) ProtoMessage()  {}

type SyncRequest struct{}

func (x *SyncRequest) Reset()         {}
func (x *SyncRequest) String() string { return "" }
func (x *SyncRequest) ProtoMessage()  {}

type SyncResponse struct {
	Success bool   `protobuf:"varint,1,opt,name=success"`
	Message string `protobuf:"bytes,2,opt,name=message"`
}

func (x *SyncResponse) Reset()         {}
func (x *SyncResponse) String() string { return x.Message }
func (x *SyncResponse) ProtoMessage()  {}

type ModeRequest struct {
	Mode      string `protobuf:"bytes,1,opt,name=mode"`
	Interface string `protobuf:"bytes,2,opt,name=interface"`
}

func (x *ModeRequest) Reset()         {}
func (x *ModeRequest) String() string { return x.Mode }
func (x *ModeRequest) ProtoMessage()  {}

type ModeResponse struct {
	Success bool   `protobuf:"varint,1,opt,name=success"`
	Message string `protobuf:"bytes,2,opt,name=message"`
}

func (x *ModeResponse) Reset()         {}
func (x *ModeResponse) String() string { return x.Message }
func (x *ModeResponse) ProtoMessage()  {}

type StatusRequest struct{}

func (x *StatusRequest) Reset()         {}
func (x *StatusRequest) String() string { return "" }
func (x *StatusRequest) ProtoMessage()  {}

type StatusResponse struct {
	DaemonVersion string             `protobuf:"bytes,1,opt,name=daemon_version"`
	Mode          string             `protobuf:"bytes,2,opt,name=mode"`
	TotalRules    int32              `protobuf:"varint,3,opt,name=total_rules"`
	Interfaces    []*InterfaceStatus `protobuf:"bytes,4,rep,name=interfaces"`
	LogEndpoint   string             `protobuf:"bytes,5,opt,name=log_endpoint"`
}

func (x *StatusResponse) Reset()         {}
func (x *StatusResponse) String() string { return "" }
func (x *StatusResponse) ProtoMessage()  {}

type InterfaceStatus struct {
	Iface        string `protobuf:"bytes,1,opt,name=iface"`
	ExplicitIps  int32  `protobuf:"varint,2,opt,name=explicit_ips"`
	Fqdns        int32  `protobuf:"varint,3,opt,name=fqdns"`
	TentativeIps int32  `protobuf:"varint,4,opt,name=tentative_ips"`
	SharedFqdns  int32  `protobuf:"varint,5,opt,name=shared_fqdns"`
	XdpAttached  bool   `protobuf:"varint,6,opt,name=xdp_attached"`
}

func (x *InterfaceStatus) Reset()         {}
func (x *InterfaceStatus) String() string { return x.Iface }
func (x *InterfaceStatus) ProtoMessage()  {}

type LogEndpointReq struct {
	Address string `protobuf:"bytes,1,opt,name=address"`
}

func (x *LogEndpointReq) Reset()         {}
func (x *LogEndpointReq) String() string { return x.Address }
func (x *LogEndpointReq) ProtoMessage()  {}

type LogEndpointResp struct {
	Success bool   `protobuf:"varint,1,opt,name=success"`
	Message string `protobuf:"bytes,2,opt,name=message"`
}

func (x *LogEndpointResp) Reset()         {}
func (x *LogEndpointResp) String() string { return x.Message }
func (x *LogEndpointResp) ProtoMessage()  {}

type LogStreamReq struct {
	Interface string `protobuf:"bytes,1,opt,name=interface"`
	Layer     string `protobuf:"bytes,2,opt,name=layer"`
}

func (x *LogStreamReq) Reset()         {}
func (x *LogStreamReq) String() string { return "" }
func (x *LogStreamReq) ProtoMessage()  {}

// ─────────────────────────────────────────────
// gRPC Service Client/Server stubs
// ─────────────────────────────────────────────

const FirewallControl_ServiceDesc_ServiceName = "firewall.FirewallControl"

type FirewallControlClient interface {
	AddRule(ctx context.Context, in *RuleRequest, opts ...grpc.CallOption) (*RuleResponse, error)
	RemoveRule(ctx context.Context, in *RuleRequest, opts ...grpc.CallOption) (*RuleResponse, error)
	ListRules(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error)
	SyncNow(ctx context.Context, in *SyncRequest, opts ...grpc.CallOption) (*SyncResponse, error)
	SetMode(ctx context.Context, in *ModeRequest, opts ...grpc.CallOption) (*ModeResponse, error)
	GetStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error)
	SetLogEndpoint(ctx context.Context, in *LogEndpointReq, opts ...grpc.CallOption) (*LogEndpointResp, error)
	StreamLogs(ctx context.Context, in *LogStreamReq, opts ...grpc.CallOption) (FirewallControl_StreamLogsClient, error)
}

type firewallControlClient struct {
	cc grpc.ClientConnInterface
}

func NewFirewallControlClient(cc grpc.ClientConnInterface) FirewallControlClient {
	return &firewallControlClient{cc}
}

func (c *firewallControlClient) AddRule(ctx context.Context, in *RuleRequest, opts ...grpc.CallOption) (*RuleResponse, error) {
	out := new(RuleResponse)
	err := c.cc.Invoke(ctx, "/firewall.FirewallControl/AddRule", in, out, opts...)
	return out, err
}

func (c *firewallControlClient) RemoveRule(ctx context.Context, in *RuleRequest, opts ...grpc.CallOption) (*RuleResponse, error) {
	out := new(RuleResponse)
	err := c.cc.Invoke(ctx, "/firewall.FirewallControl/RemoveRule", in, out, opts...)
	return out, err
}

func (c *firewallControlClient) ListRules(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error) {
	out := new(ListResponse)
	err := c.cc.Invoke(ctx, "/firewall.FirewallControl/ListRules", in, out, opts...)
	return out, err
}

func (c *firewallControlClient) SyncNow(ctx context.Context, in *SyncRequest, opts ...grpc.CallOption) (*SyncResponse, error) {
	out := new(SyncResponse)
	err := c.cc.Invoke(ctx, "/firewall.FirewallControl/SyncNow", in, out, opts...)
	return out, err
}

func (c *firewallControlClient) SetMode(ctx context.Context, in *ModeRequest, opts ...grpc.CallOption) (*ModeResponse, error) {
	out := new(ModeResponse)
	err := c.cc.Invoke(ctx, "/firewall.FirewallControl/SetMode", in, out, opts...)
	return out, err
}

func (c *firewallControlClient) GetStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error) {
	out := new(StatusResponse)
	err := c.cc.Invoke(ctx, "/firewall.FirewallControl/GetStatus", in, out, opts...)
	return out, err
}

func (c *firewallControlClient) SetLogEndpoint(ctx context.Context, in *LogEndpointReq, opts ...grpc.CallOption) (*LogEndpointResp, error) {
	out := new(LogEndpointResp)
	err := c.cc.Invoke(ctx, "/firewall.FirewallControl/SetLogEndpoint", in, out, opts...)
	return out, err
}

func (c *firewallControlClient) StreamLogs(ctx context.Context, in *LogStreamReq, opts ...grpc.CallOption) (FirewallControl_StreamLogsClient, error) {
	stream, err := c.cc.NewStream(ctx, &FirewallControl_ServiceDesc.Streams[0], "/firewall.FirewallControl/StreamLogs", opts...)
	if err != nil {
		return nil, err
	}
	x := &firewallControlStreamLogsClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type FirewallControl_StreamLogsClient interface {
	Recv() (*FirewallLog, error)
	grpc.ClientStream
}

type firewallControlStreamLogsClient struct {
	grpc.ClientStream
}

func (x *firewallControlStreamLogsClient) Recv() (*FirewallLog, error) {
	m := new(FirewallLog)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server interface
type FirewallControlServer interface {
	AddRule(context.Context, *RuleRequest) (*RuleResponse, error)
	RemoveRule(context.Context, *RuleRequest) (*RuleResponse, error)
	ListRules(context.Context, *ListRequest) (*ListResponse, error)
	SyncNow(context.Context, *SyncRequest) (*SyncResponse, error)
	SetMode(context.Context, *ModeRequest) (*ModeResponse, error)
	GetStatus(context.Context, *StatusRequest) (*StatusResponse, error)
	SetLogEndpoint(context.Context, *LogEndpointReq) (*LogEndpointResp, error)
	StreamLogs(*LogStreamReq, FirewallControl_StreamLogsServer) error
}

type UnimplementedFirewallControlServer struct{}

func (UnimplementedFirewallControlServer) AddRule(context.Context, *RuleRequest) (*RuleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "AddRule not implemented")
}
func (UnimplementedFirewallControlServer) RemoveRule(context.Context, *RuleRequest) (*RuleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "RemoveRule not implemented")
}
func (UnimplementedFirewallControlServer) ListRules(context.Context, *ListRequest) (*ListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "ListRules not implemented")
}
func (UnimplementedFirewallControlServer) SyncNow(context.Context, *SyncRequest) (*SyncResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SyncNow not implemented")
}
func (UnimplementedFirewallControlServer) SetMode(context.Context, *ModeRequest) (*ModeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "SetMode not implemented")
}
func (UnimplementedFirewallControlServer) GetStatus(context.Context, *StatusRequest) (*StatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetStatus not implemented")
}
func (UnimplementedFirewallControlServer) SetLogEndpoint(context.Context, *LogEndpointReq) (*LogEndpointResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "SetLogEndpoint not implemented")
}
func (UnimplementedFirewallControlServer) StreamLogs(*LogStreamReq, FirewallControl_StreamLogsServer) error {
	return status.Errorf(codes.Unimplemented, "StreamLogs not implemented")
}

type FirewallControl_StreamLogsServer interface {
	Send(*FirewallLog) error
	grpc.ServerStream
}

func RegisterFirewallControlServer(s grpc.ServiceRegistrar, srv FirewallControlServer) {
	s.RegisterService(&FirewallControl_ServiceDesc, srv)
}

var FirewallControl_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "firewall.FirewallControl",
	HandlerType: (*FirewallControlServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "AddRule", Handler: _FirewallControl_AddRule_Handler},
		{MethodName: "RemoveRule", Handler: _FirewallControl_RemoveRule_Handler},
		{MethodName: "ListRules", Handler: _FirewallControl_ListRules_Handler},
		{MethodName: "SyncNow", Handler: _FirewallControl_SyncNow_Handler},
		{MethodName: "SetMode", Handler: _FirewallControl_SetMode_Handler},
		{MethodName: "GetStatus", Handler: _FirewallControl_GetStatus_Handler},
		{MethodName: "SetLogEndpoint", Handler: _FirewallControl_SetLogEndpoint_Handler},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamLogs",
			Handler:       _FirewallControl_StreamLogs_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "firewall.proto",
}

func _FirewallControl_AddRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FirewallControlServer).AddRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/firewall.FirewallControl/AddRule"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FirewallControlServer).AddRule(ctx, req.(*RuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FirewallControl_RemoveRule_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RuleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FirewallControlServer).RemoveRule(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/firewall.FirewallControl/RemoveRule"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FirewallControlServer).RemoveRule(ctx, req.(*RuleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FirewallControl_ListRules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FirewallControlServer).ListRules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/firewall.FirewallControl/ListRules"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FirewallControlServer).ListRules(ctx, req.(*ListRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FirewallControl_SyncNow_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SyncRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FirewallControlServer).SyncNow(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/firewall.FirewallControl/SyncNow"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FirewallControlServer).SyncNow(ctx, req.(*SyncRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FirewallControl_SetMode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ModeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FirewallControlServer).SetMode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/firewall.FirewallControl/SetMode"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FirewallControlServer).SetMode(ctx, req.(*ModeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FirewallControl_GetStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FirewallControlServer).GetStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/firewall.FirewallControl/GetStatus"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FirewallControlServer).GetStatus(ctx, req.(*StatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FirewallControl_SetLogEndpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LogEndpointReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FirewallControlServer).SetLogEndpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/firewall.FirewallControl/SetLogEndpoint"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FirewallControlServer).SetLogEndpoint(ctx, req.(*LogEndpointReq))
	}
	return interceptor(ctx, in, info, handler)
}

type firewallControlStreamLogsServer struct {
	grpc.ServerStream
}

func (x *firewallControlStreamLogsServer) Send(m *FirewallLog) error {
	return x.ServerStream.SendMsg(m)
}

func _FirewallControl_StreamLogs_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(LogStreamReq)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FirewallControlServer).StreamLogs(m, &firewallControlStreamLogsServer{stream})
}
