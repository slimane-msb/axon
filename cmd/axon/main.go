// axon - Command-line interface for axon daemon
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/axon/proto"
)

const defaultSocket = "unix:///run/axon/daemon.sock"

var (
	socketAddr string
	ifaceName  string
)

func main() {
	root := &cobra.Command{
		Use:   "axon",
		Short: "Hybrid L3/L7 Firewall CLI",
		Long:  "Control the axon daemon — per-interface FQDN firewall with eBPF/XDP and L7 inspection.",
	}

	root.PersistentFlags().StringVarP(&socketAddr, "socket", "s", defaultSocket,
		"Daemon gRPC socket/address (unix:// or host:port)")
	root.PersistentFlags().StringVarP(&ifaceName, "interface", "i", "",
		"Network interface (empty = all)")

	// ── add ────────────────────────────────────────────────────────────
	addCmd := &cobra.Command{
		Use:   "add <ip|fqdn>",
		Short: "Add a block rule for an IP or FQDN",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleType, _ := cmd.Flags().GetString("type")
			return withClient(func(c pb.FirewallControlClient) error {
				resp, err := c.AddRule(ctx(), &pb.RuleRequest{
					Target:    args[0],
					Interface: ifaceName,
					RuleType:  ruleType,
				})
				if err != nil {
					return err
				}
				printResult(resp.Success, resp.Message)
				return nil
			})
		},
	}
	addCmd.Flags().String("type", "block", "Rule type: block|allow")

	// ── remove ─────────────────────────────────────────────────────────
	removeCmd := &cobra.Command{
		Use:     "remove <ip|fqdn>",
		Aliases: []string{"rm", "del"},
		Short:   "Remove a rule for an IP or FQDN",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(c pb.FirewallControlClient) error {
				resp, err := c.RemoveRule(ctx(), &pb.RuleRequest{
					Target:    args[0],
					Interface: ifaceName,
				})
				if err != nil {
					return err
				}
				printResult(resp.Success, resp.Message)
				return nil
			})
		},
	}

	// ── list ───────────────────────────────────────────────────────────
	listCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all firewall rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(c pb.FirewallControlClient) error {
				resp, err := c.ListRules(ctx(), &pb.ListRequest{Interface: ifaceName})
				if err != nil {
					return err
				}
				printRules(resp.Rules)
				return nil
			})
		},
	}

	// ── sync ───────────────────────────────────────────────────────────
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Force immediate DNS re-resolution",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(c pb.FirewallControlClient) error {
				resp, err := c.SyncNow(ctx(), &pb.SyncRequest{})
				if err != nil {
					return err
				}
				printResult(resp.Success, resp.Message)
				return nil
			})
		},
	}

	// ── mode ───────────────────────────────────────────────────────────
	modeCmd := &cobra.Command{
		Use:   "mode <allow-all|block-all>",
		Short: "Set firewall mode (allow-all: lists=blocklist | block-all: lists=allowlist)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := args[0]
			if m != "allow-all" && m != "block-all" {
				return fmt.Errorf("invalid mode %q, use allow-all or block-all", m)
			}
			return withClient(func(c pb.FirewallControlClient) error {
				resp, err := c.SetMode(ctx(), &pb.ModeRequest{
					Mode:      m,
					Interface: ifaceName,
				})
				if err != nil {
					return err
				}
				printResult(resp.Success, resp.Message)
				return nil
			})
		},
	}

	// ── status ─────────────────────────────────────────────────────────
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(c pb.FirewallControlClient) error {
				resp, err := c.GetStatus(ctx(), &pb.StatusRequest{})
				if err != nil {
					return err
				}
				printStatus(resp)
				return nil
			})
		},
	}

	// ── logs ───────────────────────────────────────────────────────────
	logsCmd := &cobra.Command{
		Use:   "logs",
		Short: "Stream live firewall logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			layer, _ := cmd.Flags().GetString("layer")
			follow, _ := cmd.Flags().GetBool("follow")
			addr, _   := cmd.Flags().GetString("addr")

			if !follow && addr == "" {
				// Stream from gRPC
				return withClient(func(c pb.FirewallControlClient) error {
					stream, err := c.StreamLogs(ctx(), &pb.LogStreamReq{
						Interface: ifaceName,
						Layer:     layer,
					})
					if err != nil {
						return err
					}
					fmt.Println("Streaming logs (Ctrl+C to stop)...")
					for {
						log, err := stream.Recv()
						if err == io.EOF {
							return nil
						}
						if err != nil {
							return err
						}
						printLog(log)
					}
				})
			}

			// Connect to TCP log server
			if addr == "" {
				addr = "127.0.0.1:5000"
			}
			return streamTCPLogs(addr, layer, ifaceName)
		},
	}
	logsCmd.Flags().String("layer", "", "Filter by layer: L3|L7 (empty=all)")
	logsCmd.Flags().BoolP("follow", "f", false, "Follow TCP log server stream")
	logsCmd.Flags().String("addr", "", "TCP log server address (default: 127.0.0.1:5000)")

	// ── log-endpoint ───────────────────────────────────────────────────
	logEndpointCmd := &cobra.Command{
		Use:   "log-endpoint <host:port>",
		Short: "Set the external TCP log endpoint (default: 127.0.0.1:5000)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			if _, _, err := net.SplitHostPort(addr); err != nil {
				return fmt.Errorf("invalid address %q: use host:port format", addr)
			}
			return withClient(func(c pb.FirewallControlClient) error {
				resp, err := c.SetLogEndpoint(ctx(), &pb.LogEndpointReq{Address: addr})
				if err != nil {
					return err
				}
				printResult(resp.Success, resp.Message)
				return nil
			})
		},
	}

	// Register all commands
	root.AddCommand(addCmd, removeCmd, listCmd, syncCmd, modeCmd, statusCmd, logsCmd, logEndpointCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func ctx() context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_ = cancel
	return c
}

func withClient(fn func(pb.FirewallControlClient) error) error {
	target := socketAddr

	if strings.HasPrefix(target, "unix://") {
		// Use passthrough resolver with explicit unix dialer
		// This bypasses gRPC's unix resolver which behaves inconsistently
		path := "/" + strings.TrimLeft(strings.TrimPrefix(target, "unix://"), "/")
		conn, err := grpc.Dial(
			"passthrough:///"+path,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			}),
		)
		if err != nil {
			return fmt.Errorf("connect to daemon at %s: %w\nIs axond running? (systemctl status axon)", socketAddr, err)
		}
		defer conn.Close()
		return fn(pb.NewFirewallControlClient(conn))
	}

	// TCP path
	conn, err := grpc.Dial(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("connect to daemon at %s: %w\nIs axond running? (systemctl status axon)", socketAddr, err)
	}
	defer conn.Close()
	return fn(pb.NewFirewallControlClient(conn))
}

func printResult(ok bool, msg string) {
	if ok {
		fmt.Printf("✅ %s\n", msg)
	} else {
		fmt.Printf("❌ %s\n", msg)
	}
}

func printRules(rules []*pb.Rule) {
	if len(rules) == 0 {
		fmt.Println("No rules configured.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TARGET\tINTERFACE\tTYPE\tENTRY\tRESOLVED IPs")
	fmt.Fprintln(w, "──────\t─────────\t────\t─────\t────────────")

	for _, r := range rules {
		resolved := strings.Join(r.ResolvedIps, ", ")
		if resolved == "" {
			resolved = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.Target,
			ifaceOrAll(r.Interface),
			r.RuleType,
			r.EntryType,
			resolved,
		)
	}
	w.Flush()
}

func printStatus(s *pb.StatusResponse) {
	fmt.Printf("\n🔥 axon v%s\n", s.DaemonVersion)
	fmt.Printf("   Mode:         %s\n", s.Mode)
	fmt.Printf("   Total rules:  %d\n", s.TotalRules)
	fmt.Printf("   Log endpoint: %s\n", s.LogEndpoint)
	fmt.Println()

	if len(s.Interfaces) == 0 {
		fmt.Println("   No interfaces configured.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "   INTERFACE\tEXPLICIT IPs\tFQDNs\tTENTATIVE\tSHARED L7\tXDP")
	fmt.Fprintln(w, "   ─────────\t────────────\t─────\t─────────\t─────────\t───")
	for _, is := range s.Interfaces {
		xdp := "❌"
		if is.XdpAttached {
			xdp = "✅"
		}
		fmt.Fprintf(w, "   %s\t%d\t%d\t%d\t%d\t%s\n",
			is.Iface, is.ExplicitIps, is.Fqdns, is.TentativeIps, is.SharedFqdns, xdp)
	}
	w.Flush()
	fmt.Println()
}

func printLog(log *pb.FirewallLog) {
	action := "🔴 BLOCK"
	if log.Action == "allowed" {
		action = "🟢 ALLOW"
	} else if log.Action == "redirected" {
		action = "🔵 L7   "
	}

	fmt.Printf("[%s] %s [%s] %s → %s",
		log.Timestamp,
		action,
		log.Layer,
		log.SrcIp,
		log.DstIp,
	)

	if log.DstPort > 0 {
		fmt.Printf(":%d", log.DstPort)
	}
	if log.Fqdn != "" {
		fmt.Printf(" (%s)", log.Fqdn)
	}
	if log.Interface != "" {
		fmt.Printf(" [%s]", log.Interface)
	}
	fmt.Printf(" rule=%s\n", log.RuleType)
}

func streamTCPLogs(addr, layer, iface string) error {
	fmt.Printf("Connecting to log server at %s...\n", addr)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to log server %s: %w", addr, err)
	}
	defer conn.Close()

	fmt.Println("Connected. Streaming logs (Ctrl+C to stop)...")

	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		lines := strings.Split(strings.TrimSpace(string(buf[:n])), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			// Print raw JSON or formatted
			fmt.Println(line)
		}
	}
}

func ifaceOrAll(iface string) string {
	if iface == "" {
		return "all"
	}
	return iface
}
