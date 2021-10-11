package gojtp

import (
	"fmt"
	"testing"
)

func ExampleNew() {
	// with multiple config
	_, _ = New(WithMaxArrayElementCount(6),
		WithMaxContainerDepth(7),
		WithMaxObjectKeyLength(20), WithMaxStringLength(50))

	// with single config
	_, _ = New(WithMaxStringLength(25))
}

func ExampleVerify_VerifyBytes() {
	json := []byte(`{
	"simple_string": "hello word",
    "targets": [
      {
        "req_per_second": 5,
        "duration_of_time": 1,
		"utf8Key": "Hello, 世界",
        "request": {
          "endpoint": "https://httpbin.org/get",
          "http_method": "GET",
          "payload": {
            "username": "ankur",
            "password": "ananad"
          },
		  "array_value": [
				"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstv"
			],
          "additional_header": [
            {
              "header_key": "uuid",
              "header_value": [
                "1",
                "2"
              ]
            }
          ]
        }
      },
      {
        "req_per_second": 10,
        "duration_of_time": 1,
        "request": {
          "endpoint": "https://httpbin.org/post",
          "http_method": "POST",
          "payload": {
            "username": "ankur",
            "password": "ananad"
          },
          "additional_header": [
            {
              "header_key": "uuid",
              "header_value": [
                "1",
                "2",
				"3",
				"4",
				"5",
				"Hello, 世界"
              ]
            }
          ]
        }
      }
    ]
}
	`)

	verifier1, err := New(WithMaxArrayElementCount(6),
		WithMaxContainerDepth(7),
		WithMaxObjectKeyLength(20), WithMaxStringLength(50))
	ok, err := verifier1.VerifyBytes(json)

	verifier2, err := New(WithMaxStringLength(25))
	ok, err = verifier2.VerifyBytes(json)
	fmt.Println(ok, err)
	//  Output: false jtp.maxStringValueLengthReached.Max-[25]-Allowed.Found-[47]
}

func TestIsValidateString1(t *testing.T) {
	t.Parallel()
	scenarios := []struct {
		str      string
		isString bool
	}{
		{str: `i ♥ u`, isString: false},
		{str: `"Example \u2764\ufe0f"`, isString: true},
		{str: `"Example \u2764\ufe0f`, isString: true},
		// first char should also return
	}
	for _, tc := range scenarios {
		t.Run(tc.str, func(t *testing.T) {
			_, ok := isValidateString([]byte(tc.str), 0)
			if ok != tc.isString {
				t.Errorf("Expected %v Got %v", tc.isString, ok)
			}
		})
	}
}

func TestValidStringLengthUTF8(t *testing.T) {
	t.Parallel()
	maxAllowed := 10
	scenarios := []struct {
		str []byte
		err error
	}{
		{
			str: []byte("Hello, 世界"),
			err: nil,
		},
		{
			str: []byte(`i ♥ u`),
			err: nil,
		},
		{
			str: []byte(`"Hello, World!"`),
			err: fmt.Errorf("jtp.maxStringValueLengthReached.Max-[10]-Allowed.Found-[13]"),
		},
	}

	for _, tc := range scenarios {
		t.Run(string(tc.str), func(t *testing.T) {
			e := validateStringLength(tc.str, 0, len(tc.str),
				true, maxAllowed, stringValueLength)
			if tc.err == nil && e != nil {
				t.Errorf("Expected an nil error Got - %v", e)
			}
			if tc.err != nil && e == nil {
				t.Errorf("Expected an not nil error Got - nil")
			}
			if tc.err != nil && e != nil && e.Error() != tc.err.Error() {
				t.Errorf("Expected error to be %s Got %s", tc.err.Error(), e.Error())
			}
		})
	}
}

func TestIsValidArrayCase1(t *testing.T) {
	t.Parallel()
	maxChild := 2
	scenarios := []struct {
		name string
		arr  []byte
		err  error
		ok   bool
	}{
		{
			name: "array len 3",
			arr:  []byte(`["Hello, 世界", "hello, world", "hi there"]`),
			err:  fmt.Errorf("jtp.maxArrayElementCountReached.Max-[2]-Allowed.Found-[3]"),
			ok:   false,
		},
		{
			name: "array len 2",
			arr:  []byte(`["Hello, 世界", "hi there"]`),
			err:  nil,
			ok:   true,
		},
		{
			name: "invalid array",
			arr:  []byte(`["Hello, 世界", "hi there"`),
			err:  nil,
			ok:   false,
		},
	}
	verifier := Verify{
		MaxArrayElementCount:   maxChild,
		arrayEntryCountEnabled: true,
	}
	var depth int
	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := isValidArray(tc.arr, 1, &depth, &verifier)
			if tc.ok != ok {
				t.Errorf("Expected validation %v Got %v", tc.ok, ok)
			}
			if tc.err == nil && err != nil {
				t.Errorf("Expected an not nil error Got - nil")
			}
			if tc.err != nil && err != nil && err.Error() != tc.err.Error() {
				t.Errorf("Expected error to be %s Got %s", tc.err.Error(),
					err.Error())
			}
		})
	}
}

func TestIsValidObjectCase1(t *testing.T) {
	t.Parallel()
	b := _getTestJSONBytes()
	scenarios := []struct {
		name     string
		verifier Verify
		err      error
		ok       bool
	}{
		{
			name: "array max length 4",
			verifier: Verify{
				MaxArrayElementCount:   4,
				arrayEntryCountEnabled: true,
			},
			err: fmt.Errorf("jtp.maxArrayElementCountReached.Max-[4]-Allowed.Found-[5]"),
			ok:  false,
		},
		{
			name: "string key Length max 45",
			verifier: Verify{
				stringLenEnabled: true,
				StringValueLen:   45,
			},
			err: fmt.Errorf("jtp.maxStringValueLengthReached.Max-[45]-Allowed.Found-[47]"),
			ok:  false,
		},
		{
			name: "Object Key Length max 7",
			verifier: Verify{
				objectKeyLengthEnabled: true,
				ObjectKeyLength:        7,
			},
			err: fmt.Errorf("jtp.maxKeyLengthReached.Max-[7]-Allowed.Found-[13]"),
			ok:  false,
		},
		{
			name: "Object Key Length max 7",
			verifier: Verify{
				objectKeyLengthEnabled: true,
				ObjectKeyLength:        7,
			},
			err: fmt.Errorf("jtp.maxKeyLengthReached.Max-[7]-Allowed.Found-[13]"),
			ok:  false,
		},
		{
			name: "container depth 2",
			verifier: Verify{
				jsonContainerDepthEnabled: true,
				JSONContainerDepth:        2,
			},
			err: fmt.Errorf("jtp.maxContainerDepthReached.Max-[2]-Allowed.Found-[3]"),
			ok:  false,
		},
		{
			name: "container depth 5",
			verifier: Verify{
				jsonContainerDepthEnabled: true,
				JSONContainerDepth:        5,
			},
			err: fmt.Errorf("jtp.maxContainerDepthReached.Max-[5]-Allowed.Found-[6]"),
			ok:  false,
		},
		{
			name: "Object Entry Count 4",
			verifier: Verify{
				objectEntryCountEnabled: true,
				ObjectEntryCount:        4,
			},
			err: fmt.Errorf("jtp.maxObjectEntryCountReached.Max-[4]-Allowed.Found-[5]"),
			ok:  false,
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			var depth int
			_, ok, err := isValidObject(b, 1, &depth, &tc.verifier)
			if tc.ok != ok {
				t.Errorf("Expected validation %v Got %v", tc.ok, ok)
			}
			if tc.err == nil && err != nil {
				t.Errorf("Expected an not nil error Got - nil")
			}
			if tc.err != nil && err != nil && err.Error() != tc.err.Error() {
				t.Errorf("Expected error to be %s Got %s", tc.err.Error(),
					err.Error())
			}
		})
	}
}

func TestTestifyNoJSONThreatInBytesErrorCase(t *testing.T) {
	t.Parallel()
	b := _getTestJSONBytes()
	scenarios := []struct {
		name     string
		verifier Verify
		err      error
		ok       bool
	}{
		{
			name: "array max length 4",
			verifier: Verify{
				MaxArrayElementCount:   4,
				arrayEntryCountEnabled: true,
			},
			err: fmt.Errorf("jtp.maxArrayElementCountReached.Max-[4]-Allowed.Found-[5]"),
			ok:  false,
		},
		{
			name: "string key Length max 45",
			verifier: Verify{
				stringLenEnabled: true,
				StringValueLen:   45,
			},
			err: fmt.Errorf("jtp.maxStringValueLengthReached.Max-[45]-Allowed.Found-[47]"),
			ok:  false,
		},
		{
			name: "Object Key Length max 7",
			verifier: Verify{
				objectKeyLengthEnabled: true,
				ObjectKeyLength:        7,
			},
			err: fmt.Errorf("jtp.maxKeyLengthReached.Max-[7]-Allowed." +
				"Found-[13]"),
			ok: false,
		},
		{
			name: "Object Key Length max 7",
			verifier: Verify{
				objectKeyLengthEnabled: true,
				ObjectKeyLength:        7,
			},
			err: fmt.Errorf("jtp.maxKeyLengthReached.Max-[7]-Allowed." +
				"Found-[13]"),
			ok: false,
		},
		{
			name: "container depth 2",
			verifier: Verify{
				jsonContainerDepthEnabled: true,
				JSONContainerDepth:        2,
			},
			err: fmt.Errorf("jtp.maxContainerDepthReached.Max-[2]-Allowed.Found-[3]"),
			ok:  false,
		},
		{
			name: "container depth 5",
			verifier: Verify{
				jsonContainerDepthEnabled: true,
				JSONContainerDepth:        5,
			},
			err: fmt.Errorf("jtp.maxContainerDepthReached.Max-[5]-Allowed.Found-[6]"),
			ok:  false,
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := tc.verifier.VerifyBytes(b)
			if tc.ok != ok {
				t.Errorf("Expected validation %v Got %v", tc.ok, ok)
			}
			if tc.err == nil && err != nil {
				t.Errorf("Expected an not nil error Got - nil")
			}
			if tc.err != nil && err != nil && err.Error() != tc.err.Error() {
				t.Errorf("Expected error to be %s Got %s", tc.err.Error(),
					err.Error())
			}
		})
	}
}

func TestTestifyNoJSONThreatInBytesErrorCase2(t *testing.T) {
	t.Parallel()
	b := _getMalformedTestJSONBytes()
	v := Verify{}

	t.Run("malformed json", func(t *testing.T) {
		ok, err := v.VerifyBytes(b)
		if ok != false && err != ErrInvalidJSON {
			t.Errorf("Expected Ok to Be False and Error of kind ErrInvalidJSON")
		}
	})

}

func TestTestifyNoJSONThreatInBytesPositiveCase1(t *testing.T) {
	t.Parallel()
	b := _getTestJSONBytes()
	v := Verify{}

	t.Run("Positive case 1", func(t *testing.T) {
		ok, err := v.VerifyBytes(b)
		if ok != true && err != nil {
			t.Errorf("Expected Ok to Be True and Error nil")
		}
	})

}

func TestTestifyNoJSONThreatInBytesPositiveBoundaryCase1(t *testing.T) {
	t.Parallel()
	b := _getTestJSONBytes()
	v := Verify{
		MaxArrayElementCount:      6,
		arrayEntryCountEnabled:    true,
		JSONContainerDepth:        7,
		jsonContainerDepthEnabled: true,
		ObjectKeyLength:           19,
		objectKeyLengthEnabled:    true,
		StringValueLen:            50,
		stringLenEnabled:          true,
		ObjectEntryCount:          5,
		objectEntryCountEnabled:   true,
	}

	t.Run("PositiveBoundaryCase1", func(t *testing.T) {
		ok, err := v.VerifyBytes(b)
		if ok != true && err != nil {
			t.Errorf("Expected Ok to Be True and Error nil")
		}
	})

}

func TestTestifyNoJSONThreatInBytesPositiveBoundaryCase2(t *testing.T) {
	t.Parallel()
	b := _getTestJSONBytes()
	verifier, _ := New(WithMaxArrayElementCount(6),
		WithMaxContainerDepth(7),
		WithMaxObjectKeyLength(19), WithMaxStringLength(50),
		WithMaxObjectEntryCount(5))
	t.Run("with functional option parameter", func(t *testing.T) {
		ok, err := verifier.VerifyBytes(b)
		if ok != true && err != nil {
			t.Errorf("Expected Ok to Be True and Error nil")
		}
	})

}

func BenchmarkTestifyNoThreatInBytes(b *testing.B) {
	json := _getTestJSONBytes()
	verifier, _ := New(WithMaxArrayElementCount(6),
		WithMaxContainerDepth(7),
		WithMaxObjectKeyLength(20), WithMaxStringLength(50),
		WithMaxObjectEntryCount(5))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.VerifyBytes(json)
	}
}

func _getTestJSONBytes() []byte {
	return []byte(`{
	"simple_string": "hello word",
    "targets": [
      {
        "req_per_second_1": 5,
        "duration_of_time": 1,
		"utf8Key_1": "Hello, 世界",
        "request_1": {
          "endpoint": "https://httpbin.org/get",
          "http_method": "GET",
          "payload": {
            "username": "ankur",
            "password": "ananad"
          },
		  "array_value_1": [
				"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstv"
			],
          "additional_header_1": [
            {
              "header_key": "uuid",
              "header_value": [
                "1",
                "2"
              ]
            }
          ]
        }
      },
      {
        "req_per_second": 10,
        "duration_of_time": 1,
        "request": {
          "endpoint": "https://httpbin.org/post",
          "http_method": "POST",
          "payload": {
            "username": "ankur",
            "password": "ananad"
          },
          "additional_header": [
            {
              "header_key": "uuid",
              "header_value": [
                "1",
                "2",
				"3",
				"4",
				"5",
				"Hello, 世界"
              ]
            }
          ]
        }
      }
    ]
}
	`)
}

func _getMalformedTestJSONBytes() []byte {
	return []byte(`{
	"simple_string": "hello word",
    "targets": [
      {
        "req_per_second": 5,
        "duration_of_time": 1,
		"utf8Key": "Hello, 世界",
        "request": {
          "endpoint": "https://httpbin.org/get",
          "http_method": "GET",
          "payload": {
            "username": "ankur",
            "password": "ananad"
          },
		  "array_value": [
				"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstv"
			],
          "additional_header": [
            {
              "header_key": "uuid",
              "header_value": [
                "1",
                "2"
            }
          ]
        }
      },
      {
        "req_per_second": 10,
        "duration_of_time": 1,
        "request": {
          "endpoint": "https://httpbin.org/post",
          "http_method": "POST",
          "payload": {
            "username": "ankur",
            "password": "ananad"
          },
          "additional_header": [
            {
              "header_key": "uuid",
              "header_value": [
                "1",
                "2",
				"3",
				"4",
				"5",
				"Hello, 世界"
              ]
            }
          ]
        }
      }
    ]
}
	`)
}
