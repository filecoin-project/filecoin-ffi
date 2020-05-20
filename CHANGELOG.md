# filecoin-ffi changelog

## 0.26.2

This release contains a fix for a bug which prevented unmodified miners from
generating Winning PoSts for 64GiB sectors. It also contains a fix for a bug
which was an occasional source of `bad file descriptor` errors observed during
CommP generation (our hypothesis is that the `*os.File` was being GC'ed before
the CGO call returned).

### Changelog

- github.com/filecoin-project/filecoin-ffi:
  - don't let Go garbage collect FD until FFI call returns ([filecoin-project/filecoin-ffi#84](https://github.com/filecoin-project/filecoin-ffi/pull/84))
  - fix: error if there is already a logger
  - add winning PoSt for 64 GiB (#93) ([filecoin-project/filecoin-ffi#93](https://github.com/filecoin-project/filecoin-ffi/pull/93))

### Contributors

| Contributor | Commits | Lines ± | Files Changed |
|-------------|---------|---------|---------------|
| Volker Mische | 1 | +24/-7 | 1 |
| laser | 1 | +5/-5 | 1 |
| shannon-6block | 1 | +2/-0 | 1 |

## 0.26.1

This release updates to version 0.4.1 of specs-actors, which (among other
things) extends the `RegisteredProof` types to include 64GiB sector sizes. It
also includes a fix for Window PoSt (multiple proofs were being flattened into
a single byte array) and various fixes for bellperson and neptune Rust crates.

### Changelog

- github.com/filecoin-project/filecoin-ffi:
  - Update deps revisited ([filecoin-project/filecoin-ffi#91](https://github.com/filecoin-project/filecoin-ffi/pull/91))
  - newest upstream (#88) ([filecoin-project/filecoin-ffi#88](https://github.com/filecoin-project/filecoin-ffi/pull/88))
  - update rust-filecoin-proofs-api to include PoSt fix (#87) ([filecoin-project/filecoin-ffi#87](https://github.com/filecoin-project/filecoin-ffi/pull/87))
  - upgrade to specs-actors 0.4.1 (64GiB sector support) ([filecoin-project/filecoin-ffi#85](https://github.com/filecoin-project/filecoin-ffi/pull/85))
  - Upgrade to specs-actors v0.3.0 (#81) ([filecoin-project/filecoin-ffi#81](https://github.com/filecoin-project/filecoin-ffi/pull/81))
- github.com/filecoin-project/go-amt-ipld (v2.0.1-0.20200131012142-05d80eeccc5e -> v2.0.1-0.20200424220931-6263827e49f2):
  - implement method to get first index in amt ([filecoin-project/go-amt-ipld#11](https://github.com/filecoin-project/go-amt-ipld/pull/11))
  - implement ForEachAt method to support iteration starting at a given i… ([filecoin-project/go-amt-ipld#10](https://github.com/filecoin-project/go-amt-ipld/pull/10))
- github.com/filecoin-project/specs-actors (v0.2.0 -> v0.4.1-0.20200509020627-3c96f54f3d7d):
  - Minting function maintainability (#356) ([filecoin-project/specs-actors#356](https://github.com/filecoin-project/specs-actors/pull/356))
  - support for 64GiB sectors (#355) ([filecoin-project/specs-actors#355](https://github.com/filecoin-project/specs-actors/pull/355))
  - Temporary param update (#352) ([filecoin-project/specs-actors#352](https://github.com/filecoin-project/specs-actors/pull/352))
  - document reward minting function tests (#348) ([filecoin-project/specs-actors#348](https://github.com/filecoin-project/specs-actors/pull/348))
  - puppet type and method for failed marshal to cbor (#347) ([filecoin-project/specs-actors#347](https://github.com/filecoin-project/specs-actors/pull/347))
  - Unit tests for prove commit sector (#351) ([filecoin-project/specs-actors#351](https://github.com/filecoin-project/specs-actors/pull/351))
  - Fix failure to detect faults of exactly-full top partition (#350) ([filecoin-project/specs-actors#350](https://github.com/filecoin-project/specs-actors/pull/350))
  - Fix checking of fault/recovery declaration deadlines (#349) ([filecoin-project/specs-actors#349](https://github.com/filecoin-project/specs-actors/pull/349))
  - Set ConsensusMinerMinPower to 10TiB (#344) ([filecoin-project/specs-actors#344](https://github.com/filecoin-project/specs-actors/pull/344))
  - improve deal accounting performance (#309) ([filecoin-project/specs-actors#309](https://github.com/filecoin-project/specs-actors/pull/309))
  - DeadlineInfo handles expired proving period (#343) ([filecoin-project/specs-actors#343](https://github.com/filecoin-project/specs-actors/pull/343))
  - document reward-minting taylorSeriesExpansion (#338) ([filecoin-project/specs-actors#338](https://github.com/filecoin-project/specs-actors/pull/338))
  - implement puppet actor (#290) ([filecoin-project/specs-actors#290](https://github.com/filecoin-project/specs-actors/pull/290))
  - Fix the 32GiB Window PoSt partition size again (#337) ([filecoin-project/specs-actors#337](https://github.com/filecoin-project/specs-actors/pull/337))
  - Fix seal proof type in miner actor and parameterize WPoSt partition size by it (#336) ([filecoin-project/specs-actors#336](https://github.com/filecoin-project/specs-actors/pull/336))
  - Change WPoStPartitionSectors to 2349 (#332) ([filecoin-project/specs-actors#332](https://github.com/filecoin-project/specs-actors/pull/332))
  - Remove unused SectorSize from VerifyDealsOnSectorProveCommitParams (#328) ([filecoin-project/specs-actors#328](https://github.com/filecoin-project/specs-actors/pull/328))
  - require success in reward actor send reward (#331) ([filecoin-project/specs-actors#331](https://github.com/filecoin-project/specs-actors/pull/331))
  - Power actor CreateMiner passes on value received to new actor (#327) ([filecoin-project/specs-actors#327](https://github.com/filecoin-project/specs-actors/pull/327))
  - Specify cron genesis entries (#326) ([filecoin-project/specs-actors#326](https://github.com/filecoin-project/specs-actors/pull/326))
  - Remove SysErrInternal definition, use of which is always a bug (#304) ([filecoin-project/specs-actors#304](https://github.com/filecoin-project/specs-actors/pull/304))

### Contributors

| Contributor | Commits | Lines ± | Files Changed |
|-------------|---------|---------|---------------|
| Alex North | 13 | +654/-280 | 35 |
| Whyrusleeping | 2 | +273/-437 | 13 |
| Frrist | 3 | +455/-6 | 7 |
| davidad (David A. Dalrymple) | 3 | +245/-46 | 5 |
| Jeromy | 2 | +166/-4 | 4 |
| laser | 4 | +110/-48 | 6 |
| Erin Swenson-Healey | 3 | +50/-30 | 5 |
| ZX | 1 | +48/-20 | 5 |
| nemo | 1 | +4/-56 | 2 |

## 0.26.0

This release migrates from v25 to v26 Groth parameters, which allows us to use
64GiB sectors. It also adds some safety to the CGO bindings, which were
previously sharing Go memory with C, resulting in some errors when running with
`cgocheck=2`.

### Changelog

- github.com/filecoin-project/filecoin-ffi:
  - update to v26 Groth parameters (#83) ([filecoin-project/filecoin-ffi#83](https://github.com/filecoin-project/filecoin-ffi/pull/83))
  - handle allocations for problematic structs to avoid sharing pointers-to-pointers with C (from Go) (#82) ([filecoin-project/filecoin-ffi#82](https://github.com/filecoin-project/filecoin-ffi/pull/82))

### Contributors

| Contributor | Commits | Lines ± | Files Changed |
|-------------|---------|---------|---------------|
| Erin Swenson-Healey | 2 | +514/-375 | 15 |
