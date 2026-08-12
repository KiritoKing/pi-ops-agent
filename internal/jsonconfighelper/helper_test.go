package jsonconfighelper

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestStrictDocumentPreservesUnknownBytesAndSelectsSafeScalars(t *testing.T) {
	payload := []byte(`[{"appID":"cli_one","model":"gpt-5","enabled":false,"count":12.50,"unknown":{"nested":[1,true,null]}}]`)
	document, err := parseStrictDocument(payload)
	if err != nil {
		t.Fatalf("parse strict document: %v", err)
	}
	if !bytes.Equal(document.raw, payload) {
		t.Fatal("strict parser did not retain the exact unknown-field representation")
	}
	model, err := document.selectValue("appID", "cli_one", "model")
	if err != nil || model.Kind != "string" || model.StringValue == nil || *model.StringValue != "gpt-5" {
		t.Fatalf("unexpected selected string: %#v, %v", model, err)
	}
	enabled, err := document.selectValue("appID", "cli_one", "enabled")
	if err != nil || enabled.Kind != "boolean" || enabled.BooleanValue == nil || *enabled.BooleanValue {
		t.Fatalf("unexpected selected boolean: %#v, %v", enabled, err)
	}
	count, err := document.selectValue("appID", "cli_one", "count")
	if err != nil || count.Kind != "number" || count.NumberValue == nil || *count.NumberValue != "12.50" {
		t.Fatalf("unexpected selected number: %#v, %v", count, err)
	}
	absent, err := document.selectValue("appID", "cli_one", "missing")
	if err != nil || absent.Kind != "absent" {
		t.Fatalf("unexpected absent value: %#v, %v", absent, err)
	}
	if _, err := document.selectValue("appID", "cli_one", "unknown"); err == nil {
		t.Fatal("container-valued selected field was accepted")
	}
}

func TestStrictDocumentRejectsDuplicateTrailingOversizedAndInvalidShapes(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "duplicate top level", payload: []byte(`[{"appID":"one","appID":"two"}]`)},
		{name: "duplicate nested", payload: []byte(`[{"appID":"one","nested":{"x":1,"x":2}}]`)},
		{name: "trailing value", payload: []byte(`[{"appID":"one"}] {}`)},
		{name: "top level object", payload: []byte(`{"appID":"one"}`)},
		{name: "non object element", payload: []byte(`["one"]`)},
		{name: "invalid utf8", payload: []byte{'[', '"', 0xff, '"', ']'}},
		{name: "unpaired high surrogate", payload: []byte(`[{"appID":"one","unknown":"\ud800"}]`)},
		{name: "unpaired low surrogate", payload: []byte(`[{"appID":"one","unknown":"\udc00"}]`)},
		{name: "invalid surrogate pair", payload: []byte(`[{"appID":"one","unknown":"\ud800\u0041"}]`)},
		{name: "oversized", payload: bytes.Repeat([]byte{' '}, maxJSONBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseStrictDocument(test.payload); err == nil {
				t.Fatal("unsafe JSON document was accepted")
			}
		})
	}
}

func TestStrictDocumentAcceptsValidUnicodeEscapes(t *testing.T) {
	payload := []byte(`[{"appID":"one","escaped":"\\u0061","paired":"\ud83d\ude80","literal":"�"}]`)
	if _, err := parseStrictDocument(payload); err != nil {
		t.Fatalf("valid Unicode JSON was rejected: %v", err)
	}
}

func TestSelectorMustBeUniqueAndControlSafe(t *testing.T) {
	document, err := parseStrictDocument([]byte(`[
		{"appID":"duplicate","model":"one"},
		{"appID":"duplicate","model":"two"},
		{"appID":"control","model":"line\nbreak"},
		{"appID":"format","model":"safe\u202eunsafe"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := document.selectValue("appID", "duplicate", "model"); err == nil {
		t.Fatal("duplicate selector was accepted")
	}
	if _, err := document.selectValue("appID", "missing", "model"); err == nil {
		t.Fatal("missing selector was accepted")
	}
	if _, err := document.selectValue("appID", "control", "model"); err == nil {
		t.Fatal("control-bearing selected text was accepted")
	}
	if _, err := document.selectValue("appID", "format", "model"); err == nil {
		t.Fatal("format-control-bearing selected text was accepted")
	}
}

func TestRewriteOneFieldIsDeterministicAndPreservesUnknownSemantics(t *testing.T) {
	payload := []byte(`[
		{"name":"one","model":"old","count":12.50,"unknown":{"nested":[1,true,null,{"x":"y"}]}},
		{"name":"two","model":"untouched","extra":[false,2]}
	]`)
	document, err := parseStrictDocument(payload)
	if err != nil {
		t.Fatal(err)
	}
	newModel := "new/model"
	rewritten, before, after, err := document.rewriteOneField(
		"name", "one", "model", mutateValue{Kind: "string", StringValue: &newModel},
	)
	if err != nil {
		t.Fatalf("rewrite selected field: %v", err)
	}
	if before.StringValue == nil || *before.StringValue != "old" || after.StringValue == nil || *after.StringValue != newModel {
		t.Fatalf("unexpected before/after values: %#v %#v", before, after)
	}
	parsedAfter, err := parseStrictDocument(rewritten)
	if err != nil {
		t.Fatalf("parse rewritten document: %v", err)
	}
	expected, err := parseStrictDocument([]byte(`[
		{"name":"one","model":"new/model","count":12.50,"unknown":{"nested":[1,true,null,{"x":"y"}]}},
		{"name":"two","model":"untouched","extra":[false,2]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsedAfter.root, expected.root) {
		t.Fatalf("unknown semantic values changed:\nactual: %#v\nexpected: %#v", parsedAfter.root, expected.root)
	}

	secondSource, err := parseStrictDocument(payload)
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := secondSource.rewriteOneField(
		"name", "one", "model", mutateValue{Kind: "string", StringValue: &newModel},
	)
	if err != nil || !bytes.Equal(rewritten, second) {
		t.Fatalf("whole-document rewrite was not deterministic: %q %q, %v", rewritten, second, err)
	}
}

func TestRewriteOneFieldSupportsBooleanClearAndRejectsConfusion(t *testing.T) {
	t.Run("boolean", func(t *testing.T) {
		document, err := parseStrictDocument([]byte(`[{"name":"one","enabled":false,"unknown":1}]`))
		if err != nil {
			t.Fatal(err)
		}
		value := true
		payload, before, after, err := document.rewriteOneField(
			"name", "one", "enabled", mutateValue{Kind: "boolean", BooleanValue: &value},
		)
		if err != nil || before.BooleanValue == nil || *before.BooleanValue || after.BooleanValue == nil || !*after.BooleanValue {
			t.Fatalf("unexpected boolean rewrite: %q %#v %#v %v", payload, before, after, err)
		}
	})

	t.Run("clear", func(t *testing.T) {
		document, err := parseStrictDocument([]byte(`[{"name":"one","optional":"set","unknown":1}]`))
		if err != nil {
			t.Fatal(err)
		}
		payload, before, after, err := document.rewriteOneField(
			"name", "one", "optional", mutateValue{Kind: "clear"},
		)
		if err != nil || before.Kind != "string" || after.Kind != "absent" || strings.Contains(string(payload), "optional") {
			t.Fatalf("unexpected clear rewrite: %q %#v %#v %v", payload, before, after, err)
		}
	})

	unsafe := "line\nbreak"
	formatControl := "safe\u202Eunsafe"
	value := true
	tests := []struct {
		name     string
		payload  string
		selector string
		field    string
		value    mutateValue
	}{
		{name: "selector field", payload: `[{"name":"one"}]`, selector: "name", field: "name", value: mutateValue{Kind: "clear"}},
		{name: "no-op string", payload: `[{"name":"one","model":"old"}]`, selector: "name", field: "model", value: mutateValue{Kind: "string", StringValue: stringPointer("old")}},
		{name: "no-op boolean", payload: `[{"name":"one","enabled":true}]`, selector: "name", field: "enabled", value: mutateValue{Kind: "boolean", BooleanValue: &value}},
		{name: "clear absent", payload: `[{"name":"one"}]`, selector: "name", field: "missing", value: mutateValue{Kind: "clear"}},
		{name: "container before", payload: `[{"name":"one","model":{"secret":true}}]`, selector: "name", field: "model", value: mutateValue{Kind: "clear"}},
		{name: "unsafe string", payload: `[{"name":"one","model":"old"}]`, selector: "name", field: "model", value: mutateValue{Kind: "string", StringValue: &unsafe}},
		{name: "format control", payload: `[{"name":"one","model":"old"}]`, selector: "name", field: "model", value: mutateValue{Kind: "string", StringValue: &formatControl}},
		{name: "tag confusion", payload: `[{"name":"one","model":"old"}]`, selector: "name", field: "model", value: mutateValue{Kind: "string", StringValue: stringPointer("new"), BooleanValue: &value}},
		{name: "unknown tag", payload: `[{"name":"one","model":"old"}]`, selector: "name", field: "model", value: mutateValue{Kind: "number"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := parseStrictDocument([]byte(test.payload))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := document.rewriteOneField(test.selector, "one", test.field, test.value); err == nil {
				t.Fatal("unsafe or ambiguous mutation was accepted")
			}
		})
	}
}

func stringPointer(value string) *string {
	return &value
}

func TestStrictOptionsRejectAmbiguityAndPathEscape(t *testing.T) {
	base := []string{
		"--home", "/home/alice", "--relative", ".botmux/bots.json",
		"--selector-key", "appID", "--selector-value", "cli_one", "--field", "model",
	}
	if _, err := parseInspectOptions(base); err != nil {
		t.Fatalf("valid inspect options rejected: %v", err)
	}

	tests := [][]string{
		append(append([]string{}, base...), "--field", "backendType"),
		{"--home", "/home/alice", "--relative", "../etc/passwd", "--selector-key", "appID", "--selector-value", "one", "--field", "model"},
		{"--home", "/home/alice/../alice", "--relative", ".botmux/bots.json", "--selector-key", "appID", "--selector-value", "one", "--field", "model"},
		{"--home", "/home/alice", "--relative", "/etc/passwd", "--selector-key", "appID", "--selector-value", "one", "--field", "model"},
		{"--home", "/home/alice", "--relative", ".botmux/bots.json", "--selector-key", "app.ID", "--selector-value", "one", "--field", "model"},
	}
	for index, arguments := range tests {
		if _, err := parseInspectOptions(arguments); err == nil {
			t.Fatalf("unsafe option set %d was accepted", index)
		}
	}
}

func TestInspectDirectoryOptionsRequireCleanContainedAbsolutePaths(t *testing.T) {
	valid := []string{"--root", "/srv/botmux", "--path", "/srv/botmux/workspaces/team"}
	options, err := parseInspectDirectoryOptions(valid)
	if err != nil || options.Root != "/srv/botmux" || options.Path != "/srv/botmux/workspaces/team" {
		t.Fatalf("valid inspect-directory options rejected: %#v %v", options, err)
	}
	if _, err := parseInspectDirectoryOptions([]string{"--root", "/", "--path", "/"}); err != nil {
		t.Fatalf("equal filesystem root was rejected: %v", err)
	}

	tests := [][]string{
		{"--root", "/srv/botmux", "--path", "/srv/other"},
		{"--root", "/srv/botmux", "--path", "/srv/botmux/../other"},
		{"--root", "/srv/botmux/", "--path", "/srv/botmux/work"},
		{"--root", "srv/botmux", "--path", "/srv/botmux/work"},
		{"--root", "/srv/botmux", "--path", "work"},
		{"--root", "/srv/botmux", "--path", "/srv/botmux/work", "--path", "/srv/botmux/other"},
		{"--root", "/srv/botmux", "--path", "/srv/botmux/work", "--unknown", "value"},
	}
	for index, arguments := range tests {
		if _, err := parseInspectDirectoryOptions(arguments); err == nil {
			t.Fatalf("unsafe inspect-directory option set %d was accepted: %#v", index, arguments)
		}
	}
}

func TestMutateOptionsRequireAnExactTaggedValue(t *testing.T) {
	base := []string{
		"--home", "/home/alice", "--relative", ".botmux/bots.json",
		"--selector-key", "name", "--selector-value", "cli_one", "--field", "model",
		"--stage-root", "/run/user/1000/stage", "--output", "/run/user/1000/stage/after.json",
	}
	validString := append(append([]string{}, base...), "--value-kind", "string", "--string-value", "gpt-5")
	parsed, err := parseMutateOptions(validString)
	if err != nil || parsed.Value.StringValue == nil || *parsed.Value.StringValue != "gpt-5" {
		t.Fatalf("valid string mutation rejected: %#v %v", parsed, err)
	}
	validBoolean := append(append([]string{}, base...), "--value-kind=boolean", "--boolean-value=false")
	parsed, err = parseMutateOptions(validBoolean)
	if err != nil || parsed.Value.BooleanValue == nil || *parsed.Value.BooleanValue {
		t.Fatalf("valid boolean mutation rejected: %#v %v", parsed, err)
	}
	validClear := append(append([]string{}, base...), "--value-kind", "clear")
	if _, err := parseMutateOptions(validClear); err != nil {
		t.Fatalf("valid clear mutation rejected: %v", err)
	}

	unsafeString := "safe\u202Eunsafe"
	tests := [][]string{
		append(append([]string{}, base...), "--value-kind", "string"),
		append(append([]string{}, base...), "--value-kind", "string", "--string-value", "new", "--boolean-value", "true"),
		append(append([]string{}, base...), "--value-kind", "boolean", "--boolean-value", "True"),
		append(append([]string{}, base...), "--value-kind", "clear", "--string-value", "unexpected"),
		append(append([]string{}, base...), "--value-kind", "number"),
		append(append([]string{}, base...), "--value-kind", "string", "--string-value", unsafeString),
		append(append([]string{}, validString...), "--field", "other"),
		append(append([]string{}, validString...), "--unknown", "value"),
	}
	selectorField := append([]string{}, validClear...)
	for index := range selectorField {
		if selectorField[index] == "model" {
			selectorField[index] = "name"
		}
	}
	tests = append(tests, selectorField)
	for index, arguments := range tests {
		if _, err := parseMutateOptions(arguments); err == nil {
			t.Fatalf("unsafe mutate option set %d was accepted: %#v", index, arguments)
		}
	}
}

func TestCommitOptionsRequireContainedStageAndCanonicalDistinctDigests(t *testing.T) {
	before := digestPayload([]byte("before"))
	after := digestPayload([]byte("after"))
	valid := []string{
		"--home", "/home/alice", "--relative", ".botmux/bots.json",
		"--stage-root", "/run/user/1000/stage", "--staged", "/run/user/1000/stage/after.json",
		"--expected-before", before, "--expected-after", after,
	}
	if _, err := parseCommitOptions("commit", valid); err != nil {
		t.Fatalf("valid commit options rejected: %v", err)
	}
	outside := append([]string{}, valid...)
	for index := range outside {
		if outside[index] == "/run/user/1000/stage/after.json" {
			outside[index] = "/run/user/1000/outside.json"
		}
	}
	if _, err := parseCommitOptions("commit", outside); err == nil {
		t.Fatal("staged path outside stage root was accepted")
	}
	same := append([]string{}, valid...)
	same[len(same)-1] = before
	if _, err := parseCommitOptions("commit", same); err == nil {
		t.Fatal("identical before and after digests were accepted")
	}
	upper := append([]string{}, valid...)
	upper[len(upper)-1] = strings.ToUpper(after)
	if _, err := parseCommitOptions("commit", upper); err == nil {
		t.Fatal("non-canonical digest was accepted")
	}
}

func TestRunRejectsRootIdentityBeforeDispatch(t *testing.T) {
	if osGetuidForTest() != 0 {
		t.Skip("root-only behavior")
	}
	if err := Run([]string{"inspect"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("root identity was not rejected: %v", err)
	}
}

func osGetuidForTest() int {
	// Kept in a helper so platform-neutral tests do not need build tags.
	return currentUIDForTest()
}
