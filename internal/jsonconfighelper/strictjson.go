package jsonconfighelper

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	maxJSONDepth     = 64
	maxJSONNodes     = 100000
	maxArrayElements = 4096
	maxSafeTextBytes = 512
	maxNumberBytes   = 128
)

type parsedDocument struct {
	raw  []byte
	root []any
}

func parseStrictDocument(payload []byte) (parsedDocument, error) {
	if len(payload) == 0 || len(payload) > maxJSONBytes {
		return parsedDocument{}, errors.New("JSON document has an invalid bounded size")
	}
	if !utf8.Valid(payload) {
		return parsedDocument{}, errors.New("JSON document is not valid UTF-8")
	}
	if err := validateUnicodeEscapes(payload); err != nil {
		return parsedDocument{}, err
	}
	if err := validateJSONTokens(payload); err != nil {
		return parsedDocument{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return parsedDocument{}, errors.New("decode strict JSON document")
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return parsedDocument{}, err
	}
	root, ok := decoded.([]any)
	if !ok || len(root) > maxArrayElements {
		return parsedDocument{}, errors.New("JSON document must be a bounded top-level array")
	}
	for _, item := range root {
		if _, ok := item.(map[string]any); !ok {
			return parsedDocument{}, errors.New("JSON array entries must be objects")
		}
	}
	return parsedDocument{raw: append([]byte(nil), payload...), root: root}, nil
}

// encoding/json replaces an unpaired UTF-16 surrogate escape with U+FFFD.
// Reject those escapes before decoding so a whole-document rewrite cannot
// silently change an unknown key or value. Valid surrogate pairs remain
// accepted and are semantically preserved by the decode/encode cycle.
func validateUnicodeEscapes(payload []byte) error {
	inString := false
	for index := 0; index < len(payload); index++ {
		switch payload[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			index++
			if index >= len(payload) {
				return errors.New("JSON string has a truncated escape")
			}
			if payload[index] != 'u' {
				continue
			}
			first, ok := decodeHexQuad(payload, index+1)
			if !ok {
				return errors.New("JSON string has an invalid Unicode escape")
			}
			if first >= 0xdc00 && first <= 0xdfff {
				return errors.New("JSON string has an unpaired low surrogate escape")
			}
			if first >= 0xd800 && first <= 0xdbff {
				if index+10 >= len(payload) || payload[index+5] != '\\' || payload[index+6] != 'u' {
					return errors.New("JSON string has an unpaired high surrogate escape")
				}
				second, secondOK := decodeHexQuad(payload, index+7)
				if !secondOK || second < 0xdc00 || second > 0xdfff {
					return errors.New("JSON string has an invalid surrogate pair")
				}
				index += 10
				continue
			}
			index += 4
		}
	}
	return nil
}

func decodeHexQuad(payload []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(payload) {
		return 0, false
	}
	var value uint16
	for _, digit := range payload[start : start+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func validateJSONTokens(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		if depth > maxJSONDepth {
			return errors.New("JSON document exceeds the nesting limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return errors.New("decode strict JSON token")
		}
		nodes++
		if nodes > maxJSONNodes {
			return errors.New("JSON document exceeds the node limit")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return errors.New("decode strict JSON object key")
				}
				key, keyOK := keyToken.(string)
				if !keyOK {
					return errors.New("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("JSON document contains a duplicate object key")
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim('}') {
				return errors.New("JSON object is not closed")
			}
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > maxArrayElements {
					return errors.New("JSON array exceeds the element limit")
				}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim(']') {
				return errors.New("JSON array is not closed")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	return ensureJSONEnd(decoder)
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("JSON document contains a trailing value")
	}
	return errors.New("JSON document contains trailing data")
}

func (document parsedDocument) selectValue(key, value, field string) (safeValue, error) {
	selected, err := document.selectObject(key, value)
	if err != nil {
		return safeValue{}, err
	}
	fieldValue, present := selected[field]
	return safeScalar(fieldValue, present)
}

func (document parsedDocument) selectObject(key, value string) (map[string]any, error) {
	var selected map[string]any
	matches := 0
	for _, item := range document.root {
		object := item.(map[string]any)
		candidate, ok := object[key].(string)
		if !ok || candidate != value {
			continue
		}
		selected = object
		matches++
	}
	if matches != 1 {
		return nil, errors.New("selector must identify exactly one JSON object")
	}
	return selected, nil
}

func safeScalar(fieldValue any, present bool) (safeValue, error) {
	if !present {
		return safeValue{Kind: "absent"}, nil
	}
	switch typed := fieldValue.(type) {
	case nil:
		return safeValue{Kind: "null"}, nil
	case bool:
		value := typed
		return safeValue{Kind: "boolean", BooleanValue: &value}, nil
	case string:
		if !validBoundedText(typed, maxSafeTextBytes) {
			return safeValue{}, errors.New("selected string is not bounded control-free UTF-8")
		}
		value := typed
		return safeValue{Kind: "string", StringValue: &value}, nil
	case json.Number:
		if len(typed.String()) == 0 || len(typed.String()) > maxNumberBytes {
			return safeValue{}, errors.New("selected number exceeds the bound")
		}
		value := typed.String()
		return safeValue{Kind: "number", NumberValue: &value}, nil
	default:
		return safeValue{}, errors.New("selected field must be absent or a safe scalar")
	}
}

func (document parsedDocument) rewriteOneField(
	selectorKey, selectorValue, field string,
	mutation mutateValue,
) ([]byte, safeValue, safeValue, error) {
	if selectorKey == field {
		return nil, safeValue{}, safeValue{}, errors.New("mutation cannot change the selector field")
	}
	selected, err := document.selectObject(selectorKey, selectorValue)
	if err != nil {
		return nil, safeValue{}, safeValue{}, err
	}
	before, err := safeScalar(selected[field], hasObjectKey(selected, field))
	if err != nil {
		return nil, safeValue{}, safeValue{}, err
	}
	expectedAfter, err := validatedMutationValue(mutation)
	if err != nil {
		return nil, safeValue{}, safeValue{}, err
	}
	if sameSafeValue(before, expectedAfter) {
		return nil, safeValue{}, safeValue{}, errors.New("mutation must change the selected field")
	}

	switch mutation.Kind {
	case "string":
		selected[field] = *mutation.StringValue
	case "boolean":
		selected[field] = *mutation.BooleanValue
	case "clear":
		if before.Kind == "absent" {
			return nil, safeValue{}, safeValue{}, errors.New("clear mutation requires a present selected field")
		}
		delete(selected, field)
	default:
		return nil, safeValue{}, safeValue{}, errors.New("unsupported mutation kind")
	}

	payload, err := json.Marshal(document.root)
	if err != nil || len(payload) == 0 || len(payload) > maxJSONBytes {
		return nil, safeValue{}, safeValue{}, errors.New("encode bounded rewritten JSON document")
	}
	// Reparse the exact bytes that will be written. This catches encoder/type
	// surprises and verifies that the original selector remains unique.
	rewritten, err := parseStrictDocument(payload)
	if err != nil {
		return nil, safeValue{}, safeValue{}, errors.New("validate rewritten JSON document")
	}
	after, err := rewritten.selectValue(selectorKey, selectorValue, field)
	if err != nil || !sameSafeValue(after, expectedAfter) {
		return nil, safeValue{}, safeValue{}, errors.New("rewritten field failed exact typed verification")
	}
	if digestPayload(payload) == digestPayload(document.raw) {
		return nil, safeValue{}, safeValue{}, errors.New("mutation produced an unchanged document")
	}
	return payload, before, after, nil
}

func hasObjectKey(object map[string]any, key string) bool {
	_, ok := object[key]
	return ok
}

func validatedMutationValue(value mutateValue) (safeValue, error) {
	switch value.Kind {
	case "string":
		if value.StringValue == nil || value.BooleanValue != nil || !validMutationText(*value.StringValue) {
			return safeValue{}, errors.New("invalid string mutation value")
		}
		copy := *value.StringValue
		return safeValue{Kind: "string", StringValue: &copy}, nil
	case "boolean":
		if value.BooleanValue == nil || value.StringValue != nil {
			return safeValue{}, errors.New("invalid boolean mutation value")
		}
		copy := *value.BooleanValue
		return safeValue{Kind: "boolean", BooleanValue: &copy}, nil
	case "clear":
		if value.StringValue != nil || value.BooleanValue != nil {
			return safeValue{}, errors.New("clear mutation cannot carry a value")
		}
		return safeValue{Kind: "absent"}, nil
	default:
		return safeValue{}, errors.New("mutation kind must be string, boolean, or clear")
	}
}

func sameSafeValue(left, right safeValue) bool {
	if left.Kind != right.Kind {
		return false
	}
	switch left.Kind {
	case "string":
		return left.StringValue != nil && right.StringValue != nil && *left.StringValue == *right.StringValue
	case "boolean":
		return left.BooleanValue != nil && right.BooleanValue != nil && *left.BooleanValue == *right.BooleanValue
	case "number":
		return left.NumberValue != nil && right.NumberValue != nil && *left.NumberValue == *right.NumberValue
	case "absent", "null":
		return left.StringValue == nil && right.StringValue == nil && left.BooleanValue == nil &&
			right.BooleanValue == nil && left.NumberValue == nil && right.NumberValue == nil
	default:
		return false
	}
}
