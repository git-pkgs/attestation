# attestation

Parses a sigstore bundle's DSSE envelope and the in-toto statement inside it, returning the SLSA Provenance v1 identity fields (predicate type, builder, source repository, source revision, signer identity).

Cross-ecosystem: npm, PyPI (trusted publishing), Maven Central, Cargo, and GitHub artifact attestations all emit the same DSSE-wrapped in-toto statement. One parser serves all of them.

## Install

```
go get github.com/git-pkgs/attestation
```

## Usage

```go
att, err := attestation.Parse(bundleBytes)
if err != nil { return err }
if att == nil { return nil } // not a SLSA Provenance v1 statement
fmt.Println(att.BuilderID, att.SourceRepository, att.SourceRevision)
```

`Parse` returns `(nil, nil)` for an empty body or a bundle whose DSSE payload is empty (some sigstore bundles carry non-SLSA predicates that this parser intentionally ignores). It errors only on malformed DSSE / in-toto JSON.

## What's in the bundle, what's NOT verified

`Parse` extracts identity fields. It does **not** verify the signature, certificate chain, or transparency-log inclusion proof. Pair with a separate verifier:

```
go get github.com/git-pkgs/sigstore
```

The split is deliberate: parsing identity is stdlib-only and useful in contexts where you just want to *record* what was claimed (SBOMs, audit logs, summary reports). Verification adds a heavier dependency tree (sigstore-go, TUF) and isn't always needed.

## Stdlib only

This package imports nothing beyond Go's standard library. No project-specific types, no third-party deps.

## License

MIT
