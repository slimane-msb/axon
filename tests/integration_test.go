package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	Iface  = "wlp8s0"
	IP1    = "185.99.197.3"
	IP2    = "103.224.182.246"
	Web1   = "polyglotte-institute.eu"
	Web2   = "ledvance.ewyse.agency"
	Google = "google.com"
	TSP    = "telecom-sudparis.eu"
	TSPIP  = "157.159.11.11"
)

type IfaceStatus struct {
	IPs   []string `json:"ips"`
	FQDNs []string `json:"fqdns"`
	L3    []string `json:"l3_applied"`
	L7    []string `json:"l7_applied"`
}

func getStatus(t *testing.T) IfaceStatus {
	t.Helper()
	out, err := exec.Command("../axon", "status", Iface).Output()
	if err != nil {
		t.Fatalf("axon status: %v", err)
	}
	var result map[string]IfaceStatus
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("parse status JSON: %v\noutput: %s", err, out)
	}
	return result[Iface]
}

func containsStr(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func axon(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("../axon", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("axon %v: %v\n%s", args, err, out.String())
	}
}

func checkReachable(t *testing.T, target string, want bool) {
	t.Helper()

	// Tentative de Ping
	pingOk := exec.Command("ping", "-c", "1", "-W", "1", target).Run() == nil

	// Tentative HTTP (avec transport propre pour éviter le cache des sockets)
	client := http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	httpOk := false
	for _, proto := range []string{"http://", "https://"} {
		resp, err := client.Get(proto + target)
		if err == nil {
			resp.Body.Close()
			httpOk = true
			break
		}
	}

	// LOGIQUE DE DÉTECTION ROBUSTE :
	// Si on veut REACHABLE (true) : Les deux (ou au moins un) doivent marcher.
	// Si on veut BLOCKED (false) : Soit le ping est mort (L3), soit le HTTP est mort (L7).
	
	reachable := pingOk || httpOk // Considéré accessible si l'un des deux répond

	// Cas spécial : si c'est un blocage L7, le ping sera OK mais le HTTP sera KO.
	// Donc on affine : si on veut du blocage et que le HTTP est KO, on considère que c'est gagné.
	if !want && !httpOk {
		reachable = false
	}

	if reachable != want {
		state := "REACHABLE"
		if !want {
			state = "BLOCKED"
		}
		t.Errorf("[%s] expected %s, got (ping=%v, http=%v)", target, state, pingOk, httpOk)
	}
}

func checkAll(t *testing.T, expected map[string]bool) {
	t.Helper()
	for target, want := range expected {
		target, want := target, want
		t.Run(fmt.Sprintf("%s=reachable:%v", target, want), func(t *testing.T) {
			// On laisse un tout petit battement pour le réseau
			checkReachable(t, target, want)
		})
	}
}

func assertL3(t *testing.T, val string, want bool) {
	t.Helper()
	t.Run(fmt.Sprintf("l3_applied/%s=%v", val, want), func(t *testing.T) {
		st := getStatus(t)
		if got := containsStr(st.L3, val); got != want {
			t.Errorf("want present=%v, got %v", want, got)
		}
	})
}

func assertL7(t *testing.T, val string, want bool) {
	t.Helper()
	t.Run(fmt.Sprintf("l7_applied/%s=%v", val, want), func(t *testing.T) {
		st := getStatus(t)
		if got := containsStr(st.L7, val); got != want {
			t.Errorf("want present=%v, got %v", want, got)
		}
	})
}

func TestAxonFirewall(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must run as root")
	}

	cleanup := func() {
		exec.Command("../axon", "remove-ip", Iface, IP1).Run()
		exec.Command("../axon", "remove-web", Iface, Web1).Run()
		exec.Command("../axon", "remove-web", Iface, Web2).Run()
		exec.Command("../axon", "remove-web", Iface, Google).Run()
		exec.Command("../axon", "remove-web", Iface, TSP).Run()
	}
	defer cleanup()
	cleanup()

	t.Run("S1:initial_all_reachable", func(t *testing.T) {
		checkAll(t, map[string]bool{
			IP1: true, IP2: true, Web1: true, Web2: true, Google: true, TSP: true,
		})
	})

	t.Run("S2:block_IP_direct", func(t *testing.T) {
		axon(t, "add-ip", Iface, IP1)
		time.Sleep(2 * time.Second)
		checkAll(t, map[string]bool{
			IP1: false, IP2: true, Web1: true, Web2: true, Google: true,
		})
	})

	t.Run("S3:unblock_IP", func(t *testing.T) {
		axon(t, "remove-ip", Iface, IP1)
		time.Sleep(2 * time.Second)
		checkAll(t, map[string]bool{IP1: true, IP2: true})
	})

	t.Run("S4:block_FQDN_shared_IP_does_not_affect_peer", func(t *testing.T) {
		axon(t, "add-web", Iface, Web1)
		time.Sleep(2 * time.Second)
		checkAll(t, map[string]bool{
			IP1: true, IP2: true, Web1: false, Web2: true, Google: true,
		})
	})

	t.Run("S5:block_Google_shared_IP", func(t *testing.T) {
		axon(t, "add-web", Iface, Google)
		time.Sleep(2 * time.Second)
		checkAll(t, map[string]bool{
			Web1: false, Web2: true, Google: false,
		})
	})

	t.Run("S6:unblock_Web1_Google_remains_blocked", func(t *testing.T) {
		axon(t, "remove-web", Iface, Web1)
		time.Sleep(2 * time.Second)
		checkAll(t, map[string]bool{
			Web1: true, Google: false,
		})
	})

	t.Run("S7:unblock_Google", func(t *testing.T) {
		axon(t, "remove-web", Iface, Google)
		time.Sleep(2 * time.Second)
		checkAll(t, map[string]bool{
			Google: true,
		})
		assertL7(t, Google, false)
	})

	t.Run("S8:block_FQDN_unique_IP_uses_L3", func(t *testing.T) {
		axon(t, "add-web", Iface, TSP)
		time.Sleep(2 * time.Second)
		checkAll(t, map[string]bool{
			TSP: false,
		})
		assertL3(t, TSPIP, true)
	})
}