// SPDX-License-Identifier: AGPL-3.0-only

package httpapi

import (
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/authapi"
)

func TestLoadConfigInviteCodeUnsetIsOpen(t *testing.T) {
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.InviteCode != "" {
		t.Fatalf("unset MYNE_INVITE_CODE: got %q, want empty (open registration)", cfg.InviteCode)
	}
}

func TestLoadConfigRejectsShortInviteCode(t *testing.T) {
	t.Setenv("MYNE_INVITE_CODE", strings.Repeat("a", authapi.MinInviteCodeLen-1))
	if _, err := loadConfig(); err == nil {
		t.Fatalf("short MYNE_INVITE_CODE: want a startup error, got nil")
	}
}

func TestLoadConfigAcceptsMinInviteCode(t *testing.T) {
	code := strings.Repeat("a", authapi.MinInviteCodeLen)
	t.Setenv("MYNE_INVITE_CODE", code)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.InviteCode != code {
		t.Fatalf("invite code: got %q, want %q", cfg.InviteCode, code)
	}
}
