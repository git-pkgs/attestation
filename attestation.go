// Package attestation parses identity claims from in-toto statements, DSSE
// envelopes, and sigstore bundles.
//
// The package has no dependencies outside the standard library. It's
// intentionally self-contained so it can lift out to its own module
// without dragging pin-specific types along; the npm and forge source
// paths each map the parsed result into their own Attestation shape.
//
// Parse extracts identity fields only. It does NOT verify the
// signature, certificate chain, or transparency-log inclusion proof —
// that's the job of a separate verifier (e.g., sigstore-go).
package attestation

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
)

// SLSA Provenance v1 uses these two digest names for the source-commit
// revision, depending on the producer.
const (
	digestAlgSHA1      = "sha1"
	digestAlgGitCommit = "gitCommit"
)

// Attestation is the identity-side projection of an in-toto statement. Field
// names follow the SLSA v1 vocabulary; other predicate types may leave those
// fields empty.
type Attestation struct {
	// PredicateType is the in-toto statement's predicate type URI,
	// "https://slsa.dev/provenance/v1" for SLSA Provenance v1.
	PredicateType string

	// BuilderID is runDetails.builder.id — the canonical identity of
	// the builder that produced the artifact. For GitHub-Actions builds
	// this is the workflow URI with @refs/tags/<tag>.
	BuilderID string

	// SourceRepository is the git+https URL the build was driven from,
	// with the git+ prefix and trailing .git/@refs suffix stripped.
	SourceRepository string

	// SourceRevision is the commit SHA from the build's first
	// resolvedDependencies entry that carries a sha1 or gitCommit digest.
	SourceRevision string

	// SignerIdentity is the Fulcio certificate's subject — either its
	// first URI SAN (the OIDC identity that was bound at signing time)
	// or its first email SAN if no URIs are present.
	SignerIdentity string

	// Subjects are the artifacts named by the in-toto statement and their
	// claimed digests.
	Subjects []Subject
}

// Subject is an artifact named by an in-toto statement.
type Subject struct {
	Name   string
	Digest map[string]string
}

// Parse decodes a sigstore bundle body and returns the SLSA Provenance
// v1 identity fields it claims. Returns (nil, nil) for an empty body
// or for a bundle whose DSSE payload is empty. Errors on malformed DSSE or
// in-toto JSON.
func Parse(body []byte) (*Attestation, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var b bundle
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}
	return parseEnvelope(b.DSSEEnvelope, b.VerificationMaterial)
}

// ParseAll extracts claims from raw in-toto statements, DSSE envelopes,
// sigstore bundles, JSON arrays, or JSONL streams. Unrecognized JSON objects
// are ignored. The returned identities and digests are claims, not verified
// facts.
func ParseAll(body []byte) ([]Attestation, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var attestations []Attestation
	for document := 1; ; document++ {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return attestations, nil
			}
			return nil, fmt.Errorf("decode attestation document %d: %w", document, err)
		}
		parsed, err := parseDocument(raw)
		if err != nil {
			return nil, fmt.Errorf("parse attestation document %d: %w", document, err)
		}
		attestations = append(attestations, parsed...)
	}
}

func parseDocument(raw json.RawMessage) ([]Attestation, error) {
	var documents []json.RawMessage
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &documents); err != nil {
			return nil, fmt.Errorf("decode attestation array: %w", err)
		}
		var attestations []Attestation
		for index, document := range documents {
			parsed, err := parseDocument(document)
			if err != nil {
				return nil, fmt.Errorf("parse array item %d: %w", index+1, err)
			}
			attestations = append(attestations, parsed...)
		}
		return attestations, nil
	}

	var shape documentShape
	if err := json.Unmarshal(raw, &shape); err != nil {
		return nil, err
	}
	var attestation *Attestation
	var err error
	switch {
	case shape.DSSEEnvelope != nil:
		var b bundle
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("decode bundle: %w", err)
		}
		attestation, err = parseEnvelope(b.DSSEEnvelope, b.VerificationMaterial)
	case shape.Payload != nil && (shape.PayloadType != nil || shape.Signatures != nil):
		var envelope dsseEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil, fmt.Errorf("decode DSSE envelope: %w", err)
		}
		attestation, err = parseEnvelope(envelope, verificationMaterial{})
	case shape.PredicateType != nil && shape.StatementType != nil:
		var stmt statement
		if err := json.Unmarshal(raw, &stmt); err != nil {
			return nil, fmt.Errorf("decode in-toto statement: %w", err)
		}
		attestation = attestationFromStatement(stmt)
	}
	if err != nil {
		return nil, err
	}
	if attestation == nil {
		return nil, nil
	}
	return []Attestation{*attestation}, nil
}

func parseEnvelope(envelope dsseEnvelope, material verificationMaterial) (*Attestation, error) {
	if envelope.Payload == "" {
		return nil, nil
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}
	var stmt statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("decode in-toto statement: %w", err)
	}
	attestation := attestationFromStatement(stmt)
	attestation.SignerIdentity = extractSignerIdentity(material)
	return attestation, nil
}

func attestationFromStatement(stmt statement) *Attestation {
	att := &Attestation{
		PredicateType: stmt.PredicateType,
		BuilderID:     stmt.Predicate.RunDetails.Builder.ID,
		Subjects:      make([]Subject, 0, len(stmt.Subjects)),
	}
	for _, subject := range stmt.Subjects {
		att.Subjects = append(att.Subjects, Subject(subject))
	}
	for _, dep := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		rest, ok := strings.CutPrefix(dep.URI, "git+")
		if !ok {
			continue
		}
		// Strip the @refs/<...> ref segment first so any trailing .git
		// sits at the end of the string for TrimSuffix to find.
		if i := strings.Index(rest, "@refs/"); i >= 0 {
			rest = rest[:i]
		}
		att.SourceRepository = strings.TrimSuffix(rest, ".git")
		for alg, hex := range dep.Digest {
			if alg == digestAlgSHA1 || alg == digestAlgGitCommit {
				att.SourceRevision = hex
				break
			}
		}
		break
	}
	return att
}

type documentShape struct {
	DSSEEnvelope  json.RawMessage `json:"dsseEnvelope"`
	Payload       json.RawMessage `json:"payload"`
	PayloadType   json.RawMessage `json:"payloadType"`
	Signatures    json.RawMessage `json:"signatures"`
	PredicateType json.RawMessage `json:"predicateType"`
	StatementType json.RawMessage `json:"_type"`
}

type bundle struct {
	DSSEEnvelope         dsseEnvelope         `json:"dsseEnvelope"`
	VerificationMaterial verificationMaterial `json:"verificationMaterial"`
}

type dsseEnvelope struct {
	Payload string `json:"payload"`
}

type verificationMaterial struct {
	Certificate          *cert  `json:"certificate"`
	X509CertificateChain *chain `json:"x509CertificateChain"`
}

type cert struct {
	RawBytes string `json:"rawBytes"`
}

type chain struct {
	Certificates []cert `json:"certificates"`
}

type statement struct {
	PredicateType string    `json:"predicateType"`
	Subjects      []subject `json:"subject"`
	Predicate     predicate `json:"predicate"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type predicate struct {
	BuildDefinition buildDefinition `json:"buildDefinition"`
	RunDetails      runDetails      `json:"runDetails"`
}

type buildDefinition struct {
	ResolvedDependencies []resource `json:"resolvedDependencies"`
}

type resource struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type runDetails struct {
	Builder builder `json:"builder"`
}

type builder struct {
	ID string `json:"id"`
}

func extractSignerIdentity(m verificationMaterial) string {
	var raw string
	switch {
	case m.Certificate != nil && m.Certificate.RawBytes != "":
		raw = m.Certificate.RawBytes
	case m.X509CertificateChain != nil && len(m.X509CertificateChain.Certificates) > 0:
		raw = m.X509CertificateChain.Certificates[0].RawBytes
	default:
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	if block, _ := pem.Decode(der); block != nil {
		der = block.Bytes
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	if len(c.URIs) > 0 {
		return c.URIs[0].String()
	}
	if len(c.EmailAddresses) > 0 {
		return c.EmailAddresses[0]
	}
	return ""
}
