// Package upnp provides UPnP port mapping via the upnpc CLI tool.
// Falls back gracefully if upnpc is not installed.
package upnp

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

// Mapping represents an active UPnP port mapping.
type Mapping struct {
	Port     int
	Protocol string // "UDP" or "TCP"
}

// Add creates a UPnP port mapping. Returns nil mapping if upnpc is not available.
func Add(localIP string, port int, protocol string) (*Mapping, error) {
	if _, err := exec.LookPath("upnpc"); err != nil {
		return nil, fmt.Errorf("upnpc not found: %w", err)
	}

	out, err := exec.Command("upnpc", "-a", localIP,
		fmt.Sprint(port), fmt.Sprint(port), protocol).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("upnpc add: %s: %w", strings.TrimSpace(string(out)), err)
	}

	log.Printf("UPnP: mapped %s:%d %s → %s:%d", "external", port, protocol, localIP, port)
	return &Mapping{Port: port, Protocol: protocol}, nil
}

// Remove deletes the UPnP port mapping.
func (m *Mapping) Remove() {
	if m == nil {
		return
	}
	out, err := exec.Command("upnpc", "-d", fmt.Sprint(m.Port), m.Protocol).CombinedOutput()
	if err != nil {
		log.Printf("UPnP: remove failed: %s: %v", strings.TrimSpace(string(out)), err)
		return
	}
	log.Printf("UPnP: removed %s port %d", m.Protocol, m.Port)
}

// LocalIP returns the default local IP address.
func LocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
