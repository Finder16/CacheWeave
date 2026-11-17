# Office fault recovery and `odc.faults`

Office 16.0.20527.20196 records persistent cache failures in `OfficeFileCache\odc.faults`. A permanent document-storage fault names the affected namespace and causes Office to delete that namespace the next time the file cache starts.

## Result

The observed sequence is:

1. Word reads a damaged protected stream.
2. The document revision graph reports a permanent fault and writes it under `New` in `odc.faults`.
3. Office terminates the Word process.
4. At the next file-cache start, the document-storage fault policy deletes the namespace named by the fault.
5. The record moves from `New` to `Resolved`.

This is a recovery deadline. A damaged namespace can still contain an intact vault and authenticated blobs after Word exits, but starting Word again can remove all of them.

## File format

`odc.faults` is a `Storage::KeyValueTree`: byte `0x69` followed by an LZ4 frame. CacheWeave's KVTree decoder is in `src/cacheweave/formats/decode_kvtree.py`.

| Key | Meaning |
|---|---|
| `Version` | Store version, currently 1. |
| `New`, `Poisoned`, `Resolved` | Fault subtrees keyed by fault GUID. |
| `Domain` | Component and recovery policy. |
| `Category` | Permanent or transient. |
| `Scope`, `SubScope` | Affected object. For document storage, `Scope` is the document ID and cache namespace ID. |
| `Session` | Process-private session identifier. |
| `Error` | Serialized error. |
| `AppVersion`, `Fork`, `Flights` | Office build and flight information. |
| `Attempts` | Number of handling attempts; observed as 1 after successful deletion. |

The fault domains found in this build are:

| Domain | Component |
|---|---|
| `{b561a4b8-6c0d-47e9-a9b9-000000000000}` | Document storage and the document revision graph. |
| `{c48fc055-1fc3-4e00-8574-e2acf0c5ad1c}` | Central table. |
| `{6fe47837-be4e-48bf-b5ec-805d4a1912f4}` | Dictionary storage. |
| `{9c14bb79-a8a9-468f-b9d3-672448b195c4}` | CLP. |

The permanent category is `{b68786fe-5c3d-450d-a0d5-282879035261}`; the transient category is `{60af761d-7de4-4b9a-beae-e39554ad1cab}`.

## Protected-stream failure

In the five full-damage runs, `Error` was:

```text
06 0b 05 09 db 84 e0 9a 02
```

The final LEB128 value is `0x2358025B`. `Syzygy::Cipher::DeserializeFooter` in `mso20win32client.dll` builds this `Storage::SyzygyError` when it cannot parse a protected-stream footer. The same tag was not found at another error site in the analyzed binaries.

## Reporting path

`Csi::DocumentRevisionGraphPanicCallback::PANIC` calls `Csi::ReportDocumentRevisionGraphFault` with restart enabled. The report contains a new fault GUID, the document-storage domain, its category, the document ID as scope, the serialized error, and Office build information.

`FaultManager::PersistFault` writes the record under `New`. `FaultManager::TerminateProcess` then flushes logging state and ends the process through Office telemetry's ungraceful-exit path.

Only one stored fault per domain is retained at a time. A second report for the same domain does not create an independent record.

## Handling path

`DocumentRepository::EnsureStarted` activates the document-storage, dictionary-storage, CLP, and one additional fault domain before it builds the repository.

`FaultManager::ActivateFaultDomainInternal` loads the store and runs the policy for each fault in that domain. For document storage:

- a transient fault is marked handled without removing the namespace;
- a permanent fault calls `TryRemoveDocument(scope)`;
- if document removal fails, Office treats the failure as a whole-store fault;
- after successful handling, the record moves from `New` to `Resolved`.

## Live validation

| Damage | Runs | Observation |
|---|---:|---|
| Every `.R` damaged and the first 4 KiB of `.C4` damaged | 5 | Word wrote a permanent document-storage fault, the save failed, and the process ended. The scope matched the damaged namespace in every run. |
| Next file-cache start after full damage | 1 captured before and after | The fault moved to `Resolved` with one attempt, and only the named namespace was deleted. |
| About 20% of `.R` files damaged, vault intact | 2 | Word recorded the same permanent footer fault. Before restart, 67 and 54 blobs still authenticated. At the next file-cache start, Office deleted the entire namespace in both runs. |
| Renames only | 4 completed saves | No fault was written and the save completed. |

The light-damage runs show the forensic cost of the policy: Office discarded an intact vault, authenticated content, verified document parts, and a complete older revision because one required stream was damaged.

## Recovery implications

- Acquire the cache and, when possible, the volume image before starting Word again.
- Read `odc.faults` early. A permanent document-storage record under `New` identifies the namespace Office is prepared to delete.
- Do not interpret Word's termination as proof that the entire namespace is unreadable. Authentication must be evaluated per surviving stream.
- A `Resolved` record shows that handling was attempted; it does not show that deleted bytes are unrecoverable from disk.
- Preserve the original fault store with the cache. Its scope, error, state, and Office build provide provenance for the deletion.
