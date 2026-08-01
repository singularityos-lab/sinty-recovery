package recovery

import "errors"

// The bootloader-unlock primitives are owned by the crypto agent (the sinty-crypto
// repo / libsintykey). atom-recovery calls them across this seam. The defaults
// return "not implemented" until the command wires the sintykey backend, so a
// missing backend fails closed. They are function values so tests can substitute
// spies and prove a refused unlock calls none of them.
//
// Seam contract (the crypto agent fills these in):
//
//	cryptoReadLockBit()    -> (locked bool, err error): read the TPM-NV lock bit.
//	cryptoReadVerityOff()  -> (off bool, err error): read the TPM-NV verity policy.
//	cryptoVerifyPIN()      -> (valid bool, err error): authenticate the owner.
//	cryptoWipeVar()        -> err: erase all persistent key custody under /var.
//	cryptoSetUnlockBit()   -> err: flip the TPM-NV lock bit to unlocked.
//	cryptoDisableVerity()  -> err: turn dm-verity enforcement off for the rootfs.
var errCryptoNotImplemented = errors.New("crypto primitive not implemented")

var (
	cryptoReadLockBit   = func() (bool, error) { return true, errCryptoNotImplemented }
	cryptoReadVerityOff = func() (bool, error) { return false, errCryptoNotImplemented }
	cryptoVerifyPIN     = func(int, string) (bool, error) { return false, errCryptoNotImplemented }
	cryptoWipeVar       = func() error { return errCryptoNotImplemented }
	cryptoSetUnlockBit  = func() error { return errCryptoNotImplemented }
	cryptoDisableVerity = func() error { return errCryptoNotImplemented }
)
