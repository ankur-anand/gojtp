// Package gojtp provides a fast way to validate the JSON and protect against
// vulnerable JSON content-level attacks (JSON Threat Protection)
// based on configured properties.
package gojtp

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

type (
	// Option Function Parameters to creates verifier
	Option func(*Verify) error
)

const (
	objectKeyValueLength string = "maxKeyLengthReached"
	stringValueLength    string = "maxStringValueLengthReached"
)

var (
	// ErrInvalidJSON denotes JSON is Malformed
	ErrInvalidJSON = errors.New("jtp.MalformedJSON")
)

// Verifier is the interface that wraps the basic
// Verify, VerifyBytes and VerifyString methods.
type Verifier interface {
	VerifyBytes([]byte) (bool, error)
	VerifyString(string) (bool, error)
}

// Verify Configuration Parameters.
// Verify must be created with New function.
//
//  // with some options
// 	  _, _ = New(
// 	  		 WithMaxArrayElementCount(6),
// 			 WithMaxContainerDepth(7),
// 			 WithMaxObjectKeyLength(20), WithMaxStringLength(50),
// 			 )
//
//   // with single option
// 		_, _ = New(WithMaxStringLength(25))
//
// Exported variable are for logging and reference.
type Verify struct {
	// Specifies the maximum number of elements allowed in an array.
	MaxArrayElementCount   int
	arrayEntryCountEnabled bool
	// Specifies the maximum allowed containment depth,
	// where the containers are objects or arrays.
	JSONContainerDepth        int
	jsonContainerDepthEnabled bool

	// Specifies the maximum number of entries allowed in an object
	ObjectEntryCount        int
	objectEntryCountEnabled bool
	// Specifies the maximum string length
	// allowed for a property name within an object.
	ObjectKeyLength        int
	objectKeyLengthEnabled bool
	// Specifies the maximum length allowed for a string value.
	StringValueLen   int
	stringLenEnabled bool
}

// New creates and return an Verifier with passed Option Parameters,
// with default UTF-8 text encoding.
func New(opt ...Option) (Verifier, error) {
	v := &Verify{}
	for _, setter := range opt {
		err := setter(v)
		if err != nil {
			return Verify{}, err
		}
	}

	return *v, nil
}

// WithMaxArrayElementCount Option
// Specifies the maximum number of entries (
// comma delimited values)  allowed in an array.
// zero value disable the check.
func WithMaxArrayElementCount(l int) Option {
	return func(verifier *Verify) error {
		if l == 0 {
			return nil
		}
		if l < 0 {
			return fmt.Errorf("jtp: max array element count cannot be"+
				" negative %d", l)
		}
		verifier.MaxArrayElementCount = l
		verifier.arrayEntryCountEnabled = true
		return nil
	}
}

// WithMaxContainerDepth Option
// Specifies the maximum allowed nested containers depth, within a JSON
// where the containers are objects or arrays.
// zero value disable the checks
func WithMaxContainerDepth(l int) Option {
	return func(verifier *Verify) error {
		if l == 0 {
			return nil
		}
		if l < 0 {
			return fmt.Errorf("jtp: max Container depth cannot be"+
				" negative %d", l)
		}
		verifier.JSONContainerDepth = l
		verifier.jsonContainerDepthEnabled = true
		return nil
	}
}

// WithMaxObjectKeyLength Option
// Specifies the maximum number of characters (UTF-8 encoded)
// allowed for a property(key) name within an object.
// zero value disable the checks
func WithMaxObjectKeyLength(l int) Option {
	return func(verifier *Verify) error {
		if l == 0 {
			return nil
		}
		if l < 0 {
			return fmt.Errorf("jtp: max object key length cannot be"+
				" negative %d", l)
		}
		verifier.ObjectKeyLength = l
		verifier.objectKeyLengthEnabled = true
		return nil
	}
}

// WithMaxStringLength Option
// Specifies the maximum number of characters  (
// UTF-8 encoded) in a string value.
// zero value disable the checks
func WithMaxStringLength(l int) Option {
	return func(verifier *Verify) error {
		if l == 0 {
			return nil
		}
		if l < 0 {
			return fmt.Errorf("jtp: max string length cannot be"+
				" negative %d", l)
		}
		verifier.StringValueLen = l
		verifier.stringLenEnabled = true
		return nil
	}
}

// WithMaxObjectEntryCount Option
// Specifies the maximum number of entries
// (comma delimited string:value pairs) in a single object
// zero value disable the checks
func WithMaxObjectEntryCount(l int) Option {
	return func(verifier *Verify) error {
		if l == 0 {
			return nil
		}
		if l < 0 {
			return fmt.Errorf("jtp: max array element count cannot be"+
				" negative %d", l)
		}
		verifier.ObjectEntryCount = l
		verifier.objectEntryCountEnabled = true
		return nil
	}
}

func validateStringLength(data []byte, startIndex, endIndex int,
	enabled bool, maxAllowed int,
	strType string) (err error) {
	str := data[startIndex:endIndex]
	// JSON exchange in an open ecosystem must be encoded in UTF-8.
	// https://tools.ietf.org/html/rfc8259#section-8.1
	l := utf8.RuneCount(str)
	// -2 for double quote validation skew in length
	if enabled && l-2 > maxAllowed {
		err = fmt.Errorf("jtp.%s.Max-[%d]-Allowed.Found-[%d]",
			strType, maxAllowed, l-2)
		return
	}
	return
}

// isValidateString checks if the string is valid or not
func isValidateString(data []byte, i int) (outi int,
	ok bool) {
	for ; i < len(data); i++ {
		if data[i] < ' ' {
			return i, false
		} else if data[i] == '\\' {
			//
			i++
			if i == len(data) {
				return i, false
			}
			switch data[i] {
			default:
				return i, false
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				for j := 0; j < 4; j++ {
					i++
					if i >= len(data) {
						return i, false
					}
					if !((data[i] >= '0' && data[i] <= '9') ||
						(data[i] >= 'a' && data[i] <= 'f') ||
						(data[i] >= 'A' && data[i] <= 'F')) {
						return i, false
					}
				}
			}
		} else if data[i] == '"' {
			return i + 1, true
		}
	}
	return i, false
}

func isValidArray(data []byte, i int, depth *int,
	verifier *Verify) (outi int, ok bool, err error) {
	if verifier.jsonContainerDepthEnabled && verifier.JSONContainerDepth < *depth {
		return i, false,
			fmt.Errorf("jtp.maxContainerDepthReached.Max-[%d]-Allowed."+
				"Found-[%d]",
				verifier.JSONContainerDepth, *depth)
	}
	for ; i < len(data); i++ {
		child := 0
		switch data[i] {
		default:
			for ; i < len(data); i++ {
				// can contain Any value
				if i, ok, err = validany(data, i, depth, verifier); !ok {
					return i, false, err
				}
				// children
				i, ok = isValidComma(data, i, ']')
				if !ok {
					return i, false, err
				}
				child++
				if verifier.arrayEntryCountEnabled && child > verifier.MaxArrayElementCount {
					return i, false,
						fmt.Errorf(
							"jtp.maxArrayElementCountReached."+
								"Max-[%d]-Allowed.Found-[%d]",
							verifier.MaxArrayElementCount, child)
				}
				if data[i] == ']' {
					*depth--
					return i + 1, true, err
				}
			}
		case ' ', '\t', '\n', '\r':
			continue
		case ']':
			*depth--
			return i + 1, true, err
		}
	}
	return i, false, err
}

func isValidObject(data []byte, i int, depth *int,
	verifier *Verify) (outi int, ok bool, err error) {
	if verifier.jsonContainerDepthEnabled && verifier.JSONContainerDepth < *depth {
		return i, false,
			fmt.Errorf("jtp.maxContainerDepthReached.Max-[%d]-Allowed."+
				"Found-[%d]",
				verifier.JSONContainerDepth, *depth)
	}
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			return i, false, err
		case ' ', '\t', '\n', '\r':
			continue
		case '}':
			*depth--
			return i + 1, true, err
		case '"':
			// entries
			entries := 0
		key:
			// key should be string
			tempI := i // for string length
			i, ok = isValidateString(data, i+1)
			if !ok {
				return i, false, err
			}
			entries++

			// check for entries count
			if verifier.objectEntryCountEnabled && verifier.
				ObjectEntryCount < entries {
				return i, false,
					fmt.Errorf("jtp.maxObjectEntryCountReached."+
						"Max-[%d]-Allowed.Found-[%d]",
						verifier.ObjectEntryCount, entries)
			}

			if ok {
				// validate key length
				err = validateStringLength(data, tempI, i,
					verifier.objectKeyLengthEnabled,
					verifier.ObjectKeyLength, objectKeyValueLength)
				if err != nil {
					// no further json verification done
					return i, false, err
				}
			}

			// key should be followed by :
			if i, ok = isValidColon(data, i); !ok {
				return i, false, err
			}
			// followed by Any Value
			if i, ok, err = validany(data, i, depth,
				verifier); !ok || err != nil {
				return i, false, err
			}

			if i, ok = isValidComma(data, i, '}'); !ok {
				return i, false, err
			}
			if data[i] == '}' {
				*depth--
				return i + 1, true, err
			}
			i++
			for ; i < len(data); i++ {
				switch data[i] {
				default:
					return i, false, err
				case ' ', '\t', '\n', '\r':
					continue
				case '"':
					goto key
				}
			}
			return i, false, err
		}
	}
	return i, false, err
}

func validany(data []byte, i int, depth *int,
	verifier *Verify) (outi int, ok bool, err error) {
	if verifier.jsonContainerDepthEnabled && verifier.JSONContainerDepth < *depth {
		return i, false,
			fmt.Errorf("jtp.maxContainerDepthReached.Max-[%d]-Allowed."+
				"Found-[%d]",
				verifier.JSONContainerDepth, *depth)
	}
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			return i, false, err
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			*depth++
			return isValidObject(data, i+1, depth, verifier)
		case '[':
			*depth++
			return isValidArray(data, i+1, depth, verifier)
		case '"':
			// validate string
			outi, ok = isValidateString(data, i+1)
			err = validateStringLength(data, i, outi,
				verifier.stringLenEnabled,
				verifier.StringValueLen, stringValueLength)
			return
		case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			outi, ok = isValidNumber(data, i+1)
			return
		case 't':
			outi, ok = isValidTrue(data, i+1)
			return
		case 'f':
			outi, ok = isValidFalse(data, i+1)
		case 'n':
			outi, ok = isValidNull(data, i+1)
			return
		}
	}
	return i, false, err
}

// HELPERS

func isValidTrue(data []byte, i int) (outi int, ok bool) {
	if i+3 <= len(data) && data[i] == 'r' && data[i+1] == 'u' &&
		data[i+2] == 'e' {
		return i + 3, true
	}
	return i, false
}

func isValidFalse(data []byte, i int) (outi int, ok bool) {
	if i+4 <= len(data) && data[i] == 'a' && data[i+1] == 'l' &&
		data[i+2] == 's' && data[i+3] == 'e' {
		return i + 4, true
	}
	return i, false
}

func isValidNull(data []byte, i int) (newI int, ok bool) {
	if i+3 <= len(data) && data[i] == 'u' && data[i+1] == 'l' &&
		data[i+2] == 'l' {
		return i + 3, true
	}
	return i, false
}

func isValidNumber(data []byte, i int) (newI int, ok bool) {
	i--
	// sign
	if data[i] == '-' {
		i++
	}
	// int
	if i == len(data) {
		return i, false
	}
	if data[i] == '0' {
		i++
	} else {
		for ; i < len(data); i++ {
			if data[i] >= '0' && data[i] <= '9' {
				continue
			}
			break
		}
	}
	// frac
	if i == len(data) {
		return i, true
	}
	if data[i] == '.' {
		i++
		if i == len(data) {
			return i, false
		}
		if data[i] < '0' || data[i] > '9' {
			return i, false
		}
		i++
		for ; i < len(data); i++ {
			if data[i] >= '0' && data[i] <= '9' {
				continue
			}
			break
		}
	}
	// exp
	if i == len(data) {
		return i, true
	}
	if data[i] == 'e' || data[i] == 'E' {
		i++
		if i == len(data) {
			return i, false
		}
		if data[i] == '+' || data[i] == '-' {
			i++
		}
		if i == len(data) {
			return i, false
		}
		if data[i] < '0' || data[i] > '9' {
			return i, false
		}
		i++
		for ; i < len(data); i++ {
			if data[i] >= '0' && data[i] <= '9' {
				continue
			}
			break
		}
	}
	return i, true
}

func isValidComma(data []byte, i int, end byte) (outi int, ok bool) {
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			return i, false
		case ' ', '\t', '\n', '\r':
			continue
		case ',':
			return i, true
		case end:
			return i, true
		}
	}
	return i, false
}

func isValidColon(data []byte, i int) (outi int, ok bool) {
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			return i, false
		case ' ', '\t', '\n', '\r':
			continue
		case ':':
			return i + 1, true
		}
	}
	return i, false
}

func isValidJSON(data []byte, i int, depth *int, verifier *Verify) (outi int, ok bool, err error) {
	for ; i < len(data); i++ {
		switch data[i] {
		default:
			i, ok, err = validany(data, i, depth,
				verifier)
			if !ok || err != nil {
				return i, false, err
			}
			for ; i < len(data); i++ {
				switch data[i] {
				default:
					return i, false, err
				case ' ', '\t', '\n', '\r':
					continue
				}
			}
			return i, true, err
		case ' ', '\t', '\n', '\r':
			continue
		}
	}
	return i, false, err
}

// VerifyBytes returns true if the input is valid json,
// and is JSON THREAT Protection Safe.
// A successful VerifyBytes returns err == nil,
// Callers should treat a return of true and nil as only success case.
func (v Verify) VerifyBytes(json []byte) (bool, error) {
	var depth int
	_, ok, err := isValidJSON(json, 0, &depth, &v)
	if err == nil && ok == false {
		err = ErrInvalidJSON
	}
	return ok, err
}

// VerifyString returns true if the input is valid json,
// and is JSON THREAT Protection Safe.
// A successful VerifyString returns err == nil,
// Callers should treat a return of true and nil as only success case.
func (v Verify) VerifyString(json string) (bool, error) {
	return v.VerifyBytes([]byte(json))
}
