// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"errors"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func TestDenyAllRejectsEverything(t *testing.T) {
	var a Authenticator = DenyAll{}

	// Empty token rejected.
	if _, err := a.Authenticate(nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil token: %v, want ErrUnauthenticated", err)
	}
	// Any non-empty token rejected too (no open path).
	if _, err := a.Authenticate(ids.DeviceToken{0x01, 0x02, 0x03}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("non-empty token: %v, want ErrUnauthenticated", err)
	}
}
