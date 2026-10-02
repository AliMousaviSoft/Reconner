package api

import (
	"strings"
	"testing"
)

func TestToolCatalogIsPinnedAndHasNoRetiredTools(t *testing.T) {
	for name, spec := range toolCatalog {
		switch spec.Method {
		case methodGo:
			parts := strings.Split(spec.Ref, "@")
			if len(parts) != 2 || parts[1] == "" || parts[1] == "latest" {
				t.Errorf("Go tool %q is not pinned to one version: %q", name, spec.Ref)
			}
		case methodPip:
			parts := strings.Split(spec.Ref, "==")
			if len(parts) != 2 || parts[1] == "" {
				t.Errorf("Python tool %q is not pinned to one version: %q", name, spec.Ref)
			}
		}
		if strings.Contains(spec.Ref, "@latest") {
			t.Errorf("tool %q uses a moving latest ref: %q", name, spec.Ref)
		}
	}
	// hydra and ncrack were reinstated (previously retired) to cover the
	// RDP/VNC/Telnet/SMB credential audit — see network_brute.go.
	for _, retired := range []string{"uncover", "dalfox", "gowitness"} {
		if _, ok := toolCatalog[retired]; ok {
			t.Errorf("retired/unused tool %q is still installable", retired)
		}
	}
}
