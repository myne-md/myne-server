# myne-server

[Myne](https://github.com/myne-md/myne) sync server — **Go**, zero-knowledge, self-hostable.

For the protocol specification, see [`myne/spec/protocol.md`](https://github.com/myne-md/myne/blob/main/spec/protocol.md).

## Status

**Phase 2, not yet started.** This repository will hold the Go sync server: ciphertext-blob storage, account-number authentication (simple verifier vs OPAQUE TBD per [`myne/spec/protocol.md` §11.1](https://github.com/myne-md/myne/blob/main/spec/protocol.md)), per-note version vectors, no IP logging.

The protocol treats hosted and self-hosted servers as identical trust boundaries — self-hosting changes the operator, not the security model.

## License

AGPL-3.0. See `LICENSE`.
