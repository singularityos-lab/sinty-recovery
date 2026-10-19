package recovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/atom"
)

func TestRepairLoader(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	signPub, signPriv, _ := ed25519.GenerateKey(nil)
	cert, _ := json.Marshal(map[string]any{"version": 1, "signing_pubkey": base64.StdEncoding.EncodeToString(signPub)})

	efi := t.TempDir()
	esp := filepath.Join(efi, "EFI", "atom")
	boot := filepath.Join(efi, "EFI", "BOOT", "BOOTX64.EFI")
	os.MkdirAll(esp, 0o755)
	os.MkdirAll(filepath.Dir(boot), 0o755)
	os.WriteFile(boot, []byte("MZ broken"), 0o644)
	os.WriteFile(filepath.Join(esp, "signing-cert.json"), cert, 0o644)
	os.WriteFile(filepath.Join(esp, "signing-cert.json.sig"), ed25519.Sign(rootPriv, cert), 0o644)

	img := []byte("MZ loader ATOM-LOADER-VERSION=2; body")
	src := t.TempDir()
	imgPath := filepath.Join(src, "loader.efi")
	os.WriteFile(imgPath, img, 0o644)
	cfg := Config{RootPub: rootPub, LoaderImage: imgPath, LoaderSig: imgPath + ".sig", Dirs: atom.StageDirs{ESP: esp}}

	if _, err := NewCore(cfg).RepairLoader(); err == nil {
		t.Fatal("repair succeeded without a signature")
	}
	os.WriteFile(imgPath+".sig", make([]byte, ed25519.SignatureSize), 0o644)
	if _, err := NewCore(cfg).RepairLoader(); err == nil {
		t.Fatal("repair accepted a bad signature")
	}
	if b, _ := os.ReadFile(boot); string(b) != "MZ broken" {
		t.Fatal("a refused repair touched the loader")
	}
	os.WriteFile(imgPath+".sig", ed25519.Sign(signPriv, img), 0o644)
	msg, err := NewCore(cfg).RepairLoader()
	if err != nil {
		t.Fatalf("RepairLoader: %v", err)
	}
	if b, _ := os.ReadFile(boot); string(b) != string(img) {
		t.Fatal("repair did not install the loader")
	}
	if b, _ := os.ReadFile(filepath.Join(esp, "loader-prev.efi")); string(b) != "MZ broken" {
		t.Fatal("repair did not keep the previous loader")
	}
	t.Log(msg)
}
