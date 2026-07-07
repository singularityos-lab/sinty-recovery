package recovery

import (
	"context"
	"fmt"

	"github.com/mirkobrombin/atomloops/atom"
)

// Reinstall fetches a signed image from the update server, verifies it and stages
// it into the -next slot. rootPub is the recovery image's own baked-in ROOT key:
// verification never depends on the main system, and a forged image is rejected
// whatever network served it.
func Reinstall(ctx context.Context, walPath, manifestURL, revocationURL string, rootPub []byte, dirs atom.StageDirs) (string, error) {
	msg, err := atom.Stage(ctx, walPath, manifestURL, revocationURL, rootPub, dirs)
	if err != nil {
		return "", fmt.Errorf("recovery reinstall: %w", err)
	}
	// Point the derived boot-state at the freshly staged candidate so the next
	// boot tries -next even if the old -active is the corrupt one we replaced.
	if err := atom.SyncBootState(walPath, dirs); err != nil {
		return "", fmt.Errorf("recovery reinstall: sync boot-state: %w", err)
	}
	return msg, nil
}
