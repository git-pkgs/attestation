package attestation

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func buildBundle(t *testing.T, predicateType, builderID, sourceURI, commitSHA string) []byte {
	t.Helper()
	stmtJSON := buildStatement(t, predicateType, builderID, sourceURI, commitSHA)
	b := map[string]any{
		"dsseEnvelope": map[string]any{
			"payload": base64.StdEncoding.EncodeToString(stmtJSON),
		},
	}
	out, _ := json.Marshal(b)
	return out
}

func buildStatement(t *testing.T, predicateType, builderID, sourceURI, commitSHA string) []byte {
	t.Helper()
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": predicateType,
		"subject": []map[string]any{
			{"name": "dist/example.tar.gz", "digest": map[string]string{"sha256": "0123456789abcdef"}},
		},
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"resolvedDependencies": []map[string]any{
					{"uri": sourceURI, "digest": map[string]string{"gitCommit": commitSHA}},
				},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": builderID},
			},
		},
	}
	out, _ := json.Marshal(stmt)
	return out
}

func buildEnvelope(t *testing.T, statement []byte) []byte {
	t.Helper()
	out, _ := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []any{},
	})
	return out
}

func TestParse_HappyPath(t *testing.T) {
	body := buildBundle(t,
		"https://slsa.dev/provenance/v1",
		"https://github.com/owner/builder/.github/workflows/release.yml@refs/tags/v1",
		"git+https://github.com/owner/repo.git@refs/heads/main",
		"deadbeef0123456789abcdef0123456789abcdef")
	att, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if att == nil {
		t.Fatal("Parse returned nil for valid bundle")
	}
	if att.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("PredicateType = %q", att.PredicateType)
	}
	if att.BuilderID != "https://github.com/owner/builder/.github/workflows/release.yml@refs/tags/v1" {
		t.Errorf("BuilderID = %q", att.BuilderID)
	}
	if att.SourceRepository != "https://github.com/owner/repo" {
		t.Errorf("SourceRepository = %q, want git+ prefix stripped and @refs/ trimmed", att.SourceRepository)
	}
	if att.SourceRevision != "deadbeef0123456789abcdef0123456789abcdef" {
		t.Errorf("SourceRevision = %q", att.SourceRevision)
	}
	if len(att.Subjects) != 1 || att.Subjects[0].Name != "dist/example.tar.gz" ||
		att.Subjects[0].Digest["sha256"] != "0123456789abcdef" {
		t.Errorf("Subjects = %#v", att.Subjects)
	}
}

func TestParseAllDocumentForms(t *testing.T) {
	statement := buildStatement(t,
		"https://slsa.dev/provenance/v1",
		"https://github.com/owner/builder/.github/workflows/release.yml@refs/tags/v1",
		"git+https://github.com/owner/repo.git@refs/heads/main",
		"deadbeef0123456789abcdef0123456789abcdef")
	envelope := buildEnvelope(t, statement)
	bundle := buildBundle(t,
		"https://slsa.dev/provenance/v1",
		"https://github.com/owner/builder/.github/workflows/release.yml@refs/tags/v1",
		"git+https://github.com/owner/repo.git@refs/heads/main",
		"deadbeef0123456789abcdef0123456789abcdef")
	body := append(append(append([]byte{}, statement...), '\n'), envelope...)
	body = append(append(body, '\n'), bundle...)

	attestations, err := ParseAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 3 {
		t.Fatalf("attestations = %#v", attestations)
	}
	for _, attestation := range attestations {
		if attestation.PredicateType != "https://slsa.dev/provenance/v1" ||
			len(attestation.Subjects) != 1 || attestation.Subjects[0].Name != "dist/example.tar.gz" {
			t.Errorf("attestation = %#v", attestation)
		}
	}
}

func TestParseAllArrayAndUnrecognizedObject(t *testing.T) {
	statement := buildStatement(t, "https://example.com/predicate/v1", "", "", "")
	body := append([]byte(`[{"name":"unrelated"},`), statement...)
	body = append(body, ']')

	attestations, err := ParseAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 || attestations[0].PredicateType != "https://example.com/predicate/v1" {
		t.Fatalf("attestations = %#v", attestations)
	}
}

func TestParseAllIgnoresUnrecognizedFieldTypes(t *testing.T) {
	statement := buildStatement(t, "https://example.com/predicate/v1", "", "", "")
	body := append(append(statement, '\n'), []byte(`{"payload":123,"predicateType":[],"name":"unrelated"}`)...)

	attestations, err := ParseAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 || attestations[0].PredicateType != "https://example.com/predicate/v1" {
		t.Fatalf("attestations = %#v", attestations)
	}
}

func TestParseAllRejectsRecognizedMalformedDocuments(t *testing.T) {
	for _, body := range []string{
		`{"payload":123,"payloadType":"application/vnd.in-toto+json","signatures":[]}`,
		`{"_type":"https://in-toto.io/Statement/v1","predicateType":[]}`,
	} {
		if _, err := ParseAll([]byte(body)); err == nil {
			t.Errorf("ParseAll accepted %s", body)
		}
	}
}

func TestParseAllMalformedDocument(t *testing.T) {
	if _, err := ParseAll([]byte("{}\n{not-json")); err == nil {
		t.Fatal("ParseAll accepted malformed JSONL")
	}
}

func TestParse_Empty(t *testing.T) {
	att, err := Parse(nil)
	if err != nil || att != nil {
		t.Errorf("Parse(nil) = (%v, %v), want (nil, nil)", att, err)
	}
}

func TestParse_EmptyPayload(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"dsseEnvelope": map[string]any{"payload": ""}})
	att, err := Parse(body)
	if err != nil || att != nil {
		t.Errorf("Parse(empty-payload) = (%v, %v), want (nil, nil)", att, err)
	}
}

func TestParse_MalformedJSON(t *testing.T) {
	if _, err := Parse([]byte("{not-json")); err == nil {
		t.Error("Parse(garbage) should error")
	}
}

func TestParse_NonGitURI(t *testing.T) {
	body := buildBundle(t,
		"https://slsa.dev/provenance/v1",
		"https://builder/",
		"https://example.com/not-a-git-uri", // missing git+ prefix
		"deadbeef")
	att, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if att.SourceRepository != "" {
		t.Errorf("SourceRepository = %q, want empty when no git+ URI in resolvedDependencies", att.SourceRepository)
	}
	if att.SourceRevision != "" {
		t.Errorf("SourceRevision = %q, want empty when no git+ URI matched", att.SourceRevision)
	}
}
