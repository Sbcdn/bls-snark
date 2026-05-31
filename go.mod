module github.com/sbcdn/bls-snark

go 1.25.7

// circom2gnark (Phase B only) is added via `go get github.com/vocdoni/circom2gnark@latest`
// at the start of Phase B work, and pinned in this file after that. Do NOT leave it
// floating once added.

// Notes:
//   - gnark v0.15.0 requires gnark-crypto v0.20.1 (verified in archived v0.15.0 go.mod).
//   - Go 1.25.7 matches the upstream gnark module declaration exactly.
//   - zerolog v1.34.0 matches what gnark v0.15.0 already pulls in, avoiding `go mod tidy` churn.
//   - cobra v1.10.2 is the version already indirect-required by gnark master (post-v0.15.0);
//     align here so we never see a conflict.

require (
	github.com/consensys/gnark v0.15.0
	github.com/consensys/gnark-crypto v0.20.1
	github.com/rs/zerolog v1.34.0
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/google/pprof v0.0.0-20260202012954-cb029daf43ef // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
