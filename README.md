# attestation

Parses identity claims from raw in-toto statements, DSSE envelopes, and sigstore bundles. It returns the predicate type, subjects and digests, builder, source repository, source revision, and signer identity when present.

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

`Parse` returns `(nil, nil)` for an empty body or a bundle whose DSSE payload is empty. It errors on malformed DSSE or in-toto JSON.

Use `ParseAll` for committed attestation files. It accepts raw statements, DSSE envelopes, sigstore bundles, JSON arrays, and JSONL streams:

```go
claims, err := attestation.ParseAll(fileBytes)
if err != nil { return err }
for _, claim := range claims {
    fmt.Println(claim.PredicateType, claim.Subjects)
}
```

Unrecognized JSON objects are ignored. The returned values are claims made by the document.

## What's in the bundle, what's NOT verified

`Parse` extracts identity fields. It does **not** verify the signature, certificate chain, or transparency-log inclusion proof. Pair with a separate verifier:

```
go get github.com/git-pkgs/sigstore
```

The split is deliberate: parsing identity is stdlib-only and useful in contexts where you just want to *record* what was claimed (SBOMs, audit logs, summary reports). Verification adds a heavier dependency tree (sigstore-go, TUF) and isn't always needed.

## Stdlib only

This package imports nothing beyond Go's standard library. No project-specific types, no third-party deps.

## License

[MIT](LICENSE).
