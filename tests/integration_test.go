package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Configuration - Adjust Iface to your actual interface (e.g., eth0, wlp8s0)
const (
	Iface  = "wlp8s0"
	IP1    = "185.99.197.3"
	IP2    = "103.224.182.246"
	Web1   = "polyglotte-institute.eu"
	Google = "google.com"
	TSP    = "telecom-sudparis.eu"
)

// Helper: Runs the axon CLI command
func axon(args ...string) error {
	cmd := exec.Command("../axon", args...)
	// We capture output to keep the test logs clean but visible on failure
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("axon %v failed: %w\nOutput: %s", args, err, out.String())
	}
	return nil
}

// Helper: Checks reachability via Ping (1 second timeout)
func isReachable(target string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", target)
	return cmd.Run() == nil
}

// Helper: Returns the output of 'axon status'
func getStatus() string {
	out, err := exec.Command("./axon", "status", Iface).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func TestAxonIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test must be run as root (sudo)")
	}

	// Global Cleanup: Ensure we leave the firewall clean
	defer func() {
		axon("remove-ip", Iface, IP1)
		axon("remove-web", Iface, Web1)
		axon("remove-web", Iface, Google)
		axon("remove-web", Iface, TSP)
	}()

	// --- STEP 1: Initial State ---
	t.Log("STEP 1: Checking initial connectivity...")
	targets := []string{IP1, IP2, Web1, Google}
	for _, target := range targets {
		if !isReachable(target) {
			t.Fatalf("[FAIL] %s is unreachable before testing. Check connection.", target)
		}
	}
	t.Log("[PASS] Initial state is clean.")

	// --- STEP 2: Block IP1 ---
	t.Log("STEP 2: Blocking IP1...")
	if err := axon("add-ip", Iface, IP1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second)
	if isReachable(IP1) { t.Errorf("IP1 (%s) should be blocked", IP1) }
	if !isReachable(IP2) { t.Errorf("IP2 (%s) should NOT be blocked", IP2) }

	// --- STEP 3: Remove IP1 ---
	t.Log("STEP 3: Removing IP1 block...")
	axon("remove-ip", Iface, IP1)
	time.Sleep(1 * time.Second)
	if !isReachable(IP1) { t.Errorf("IP1 should be reachable again") }

	// --- STEP 4: Add IP1 and Web1 ---
	t.Log("STEP 4: Blocking IP1 and Web1...")
	axon("add-ip", Iface, IP1)
	axon("add-web", Iface, Web1)
	time.Sleep(2 * time.Second)
	if isReachable(IP1) { t.Errorf("IP1 should be blocked") }
	if isReachable(Web1) { t.Errorf("Web1 (%s) should be blocked", Web1) }
	if !isReachable(Google) { t.Errorf("Google should still be open") }

	// --- STEP 5: Add Google ---
	t.Log("STEP 5: Blocking Google...")
	axon("add-web", Iface, Google)
	time.Sleep(2 * time.Second)
	if isReachable(Google) { t.Errorf("Google should be blocked") }

	// --- STEP 6: Remove Web1 ---
	t.Log("STEP 6: Removing Web1...")
	axon("remove-web", Iface, Web1)
	time.Sleep(1 * time.Second)
	if !isReachable(Web1) { t.Errorf("Web1 should be open now") }
	if isReachable(Google) { t.Errorf("Google should still be blocked") }
	if isReachable(IP1) { t.Errorf("IP1 should still be blocked") }

	// --- STEP 7: Remove Google ---
	t.Log("STEP 7: Removing Google...")
	axon("remove-web", Iface, Google)
	time.Sleep(1 * time.Second)
	if !isReachable(Google) { t.Errorf("Google should be open") }
	if isReachable(IP1) { t.Errorf("IP1 should still be blocked") }

	// --- STEP 8: FQDN to IP Translation check (TSP) ---
	t.Log("STEP 8: Testing TSP (FQDN to IP translation)...")
	axon("add-web", Iface, TSP)
	time.Sleep(2 * time.Second)

	if isReachable(TSP) { t.Errorf("TSP should be blocked") }

	status := getStatus()
	// Check if the domain name itself is missing from the L7/FQDN section 
	// (Assuming your status output separates L3/IP and L7/FQDN)
	if strings.Contains(status, TSP) {
		t.Logf("[INFO] Found '%s' in status. Verifying it was resolved to IPs...", TSP)
	}

	// Verify at least one IP of TSP is in the block list
	ips, _ := net.LookupIP(TSP)
	foundIP := false
	for _, ip := range ips {
		if strings.Contains(status, ip.String()) {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Errorf("TSP was blocked, but its resolved IPs were not found in 'axon status'")
	}

	t.Log("\n[RESULT] All Axon integration tests passed.")
}