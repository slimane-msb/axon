// Package grpc implements the FirewallControl gRPC server.
package grpc

import (
    "context"
    "fmt"
    "net"
    "os"
    "strings"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"

    "github.com/axon/internal/daemon"
    "github.com/axon/internal/logging"
    pb "github.com/axon/proto"
)

// Server is the gRPC server for the firewall daemon
type Server struct {
	pb.UnimplementedFirewallControlServer
	d      *daemon.Daemon
	logger *logging.Logger
}

// NewServer creates a new gRPC server
func NewServer(d *daemon.Daemon) *Server {
	return &Server{
		d:      d,
		logger: logging.NewLogger("grpc"),
	}
}

// Listen starts the gRPC server on addr. Handles both tcp:// and unix://
// Listen starts the gRPC server on addr. Handles both tcp:// and unix://

func (s *Server) Listen(addr string) error {
	var ln net.Listener
	var err error

	if strings.HasPrefix(addr, "unix://") {
		path := strings.TrimPrefix(addr, "unix://")
		os.Remove(path)
		ln, err = net.Listen("unix", path)
	} else {
		ln, err = net.Listen("tcp", addr)
	}

	if err != nil {
		return fmt.Errorf("gRPC listen %s: %w", addr, err)
	}

	grpcSrv := grpc.NewServer(
		grpc.MaxConcurrentStreams(100),
		grpc.ConnectionTimeout(30*time.Second),
	)

	pb.RegisterFirewallControlServer(grpcSrv, s)

	s.logger.Infof("gRPC server listening on %s", addr)
	return grpcSrv.Serve(ln)
}

// ─────────────────────────────────────────────
// RPC Implementations
// ─────────────────────────────────────────────

func (s *Server) AddRule(ctx context.Context, req *pb.RuleRequest) (*pb.RuleResponse, error) {
	if req.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	ruleType := req.RuleType
	if ruleType == "" {
		ruleType = "block"
	}

	if err := s.d.AddRule(req.Interface, req.Target, ruleType); err != nil {
		return &pb.RuleResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.RuleResponse{
		Success: true,
		Message: fmt.Sprintf("Rule added: %s on %s (%s)", req.Target, ifaceOrAll(req.Interface), ruleType),
	}, nil
}

func (s *Server) RemoveRule(ctx context.Context, req *pb.RuleRequest) (*pb.RuleResponse, error) {
	if req.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}

	if err := s.d.RemoveRule(req.Interface, req.Target); err != nil {
		return &pb.RuleResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.RuleResponse{
		Success: true,
		Message: fmt.Sprintf("Rule removed: %s from %s", req.Target, ifaceOrAll(req.Interface)),
	}, nil
}

func (s *Server) ListRules(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	rules := s.d.ListRules(req.Interface)

	var pbRules []*pb.Rule
	for _, r := range rules {
		pbRules = append(pbRules, &pb.Rule{
			Target:      r.Target,
			Interface:   r.Interface,
			RuleType:    r.RuleType,
			EntryType:   r.EntryType,
			ResolvedIps: r.ResolvedIPs,
			TtlSeconds:  r.TTL,
		})
	}

	return &pb.ListResponse{Rules: pbRules}, nil
}

func (s *Server) SyncNow(ctx context.Context, _ *pb.SyncRequest) (*pb.SyncResponse, error) {
	s.d.SyncNow()
	return &pb.SyncResponse{
		Success: true,
		Message: "DNS sync triggered",
	}, nil
}

func (s *Server) SetMode(ctx context.Context, req *pb.ModeRequest) (*pb.ModeResponse, error) {
	if err := s.d.SetMode(req.Interface, req.Mode); err != nil {
		return &pb.ModeResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.ModeResponse{
		Success: true,
		Message: fmt.Sprintf("Mode set to %s on %s", req.Mode, ifaceOrAll(req.Interface)),
	}, nil
}

func (s *Server) GetStatus(ctx context.Context, _ *pb.StatusRequest) (*pb.StatusResponse, error) {
	st := s.d.GetStatus()

	var ifaceStatuses []*pb.InterfaceStatus
	for _, is := range st.Interfaces {
		ifaceStatuses = append(ifaceStatuses, &pb.InterfaceStatus{
			Iface:        is.Iface,
			ExplicitIps:  int32(is.ExplicitIPs),
			Fqdns:        int32(is.FQDNs),
			TentativeIps: int32(is.TentativeIPs),
			SharedFqdns:  int32(is.SharedFQDNs),
			XdpAttached:  is.XDPAttached,
		})
	}

	return &pb.StatusResponse{
		DaemonVersion: st.Version,
		Mode:          st.Mode,
		TotalRules:    int32(st.TotalRules),
		Interfaces:    ifaceStatuses,
		LogEndpoint:   st.LogEndpoint,
	}, nil
}

func (s *Server) SetLogEndpoint(ctx context.Context, req *pb.LogEndpointReq) (*pb.LogEndpointResp, error) {
	if req.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "address is required")
	}

	// Validate address format
	if _, _, err := net.SplitHostPort(req.Address); err != nil {
		return &pb.LogEndpointResp{
			Success: false,
			Message: fmt.Sprintf("invalid address format (use host:port): %v", err),
		}, nil
	}

	if err := s.d.SetLogEndpoint(req.Address); err != nil {
		return &pb.LogEndpointResp{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.LogEndpointResp{
		Success: true,
		Message: fmt.Sprintf("Log endpoint set to %s", req.Address),
	}, nil
}

func (s *Server) StreamLogs(req *pb.LogStreamReq, stream pb.FirewallControl_StreamLogsServer) error {
	subID := fmt.Sprintf("grpc-stream-%d", time.Now().UnixNano())
	ch := s.d.Hub().Subscribe(subID, 500)
	defer s.d.Hub().Unsubscribe(subID)

	s.logger.Infof("Log stream subscriber connected: %s", subID)

	for {
		select {
		case <-stream.Context().Done():
			s.logger.Infof("Log stream subscriber disconnected: %s", subID)
			return nil

		case log, ok := <-ch:
			if !ok {
				return nil
			}

			// Filter by interface if requested
			if req.Interface != "" && log.Interface != req.Interface {
				continue
			}

			// Filter by layer if requested
			if req.Layer != "" && log.Layer != req.Layer {
				continue
			}

			pbLog := &pb.FirewallLog{
				Timestamp: log.Timestamp,
				Interface: log.Interface,
				SrcIp:     log.SrcIP,
				DstIp:     log.DstIP,
				Fqdn:      log.FQDN,
				RuleType:  log.RuleType,
				Action:    log.Action,
				SrcPort:   log.SrcPort,
				DstPort:   log.DstPort,
				Protocol:  log.Protocol,
				Layer:     log.Layer,
			}

			if err := stream.Send(pbLog); err != nil {
				return err
			}
		}
	}
}

func ifaceOrAll(iface string) string {
	if iface == "" {
		return "all"
	}
	return iface
}