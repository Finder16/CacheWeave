# Documentation

- [Research summary](research-summary.md): scope, findings, evaluation, limits, and acquisition notes.

## Internals

These notes cover Office `16.0.20527.20196` x64. Addresses are RVAs in that build's binaries.

| Note | Topic |
|---|---|
| [odc-architecture.md](internals/odc-architecture.md) | Which Office module does what, the cache lifecycle, the upload and revision flow |
| [physical-storage.md](internals/physical-storage.md) | The storage stack, cache folder layout, object names and their Base32 forms |
| [resident-properties.md](internals/resident-properties.md) | The `.C4` resident properties: the Terse v2 envelope, `DocumentMetadata`, storage revisions, audit log |
| [protected-storage.md](internals/protected-storage.md) | Protected streams (`e_*.R`): shards, footers, read order; the `_vault` layout |
| [crypt-session.md](internals/crypt-session.md) | Crypt sessions: key derivation, stream-key unwrap, IVs, and the match with MS-OFFCRYPTO Agile encryption |
| [encryption-providers.md](internals/encryption-providers.md) | The vault's protection providers: Windows DPAPI, Enterprise Data Protection, IRM |
| [arx-container.md](internals/arx-container.md) | The `0.ARX` volume: superblock, allocator, file index, buckets |
| [fault-recovery.md](internals/fault-recovery.md) | `odc.faults` and the deletion of faulted documents at the next start |

These pages contain the stable results of the research. Implementation paths refer to the public package under `src/cacheweave/`. Run identifiers are retained only where a sample size or a particular observation matters; raw captures, binaries, lab automation, and chronological research notes are not part of the distribution.
