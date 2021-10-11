<p align="center">
<img 
    src="gojtp.png" 
    width="240" height="78" border="0" alt="GOJTP">
<br>
<a href="https://godoc.org/github.com/ankur-anand/gojtp"><img src="https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square" alt="GoDoc"></a>
</p>

<p align="center">⚡️ A high-performance, zero allocation, dynamic JSON Threat
 Protection in
 pure Go. 🔥</p>

Package gojtp provides a fast way to **validate the dynamic JSON** and protect
 against
 vulnerable JSON content-level attacks (JSON Threat Protection) based on
 configured properties.
 
**It also validate the JSON and if JSON is Invalid it will return an error.**

### What is JSON Threat Protection

JSON requests are susceptible to attacks characterized by unusual inflation 
of elements and nesting levels. 
Attackers use recursive techniques to consume memory resources by using huge
 json files to overwhelm the parser and eventually crash the service.

JSON threat protection is terms that describe the way to minimize the risk from such attacks 
by defining few limits on the json structure like length and depth validation
 on a json, and helps protect your applications from such intrusions.

### Getting Started
Installing
To start using gojtp, install Go and run go get:

`$ go get -u github.com/ankur-anand/gojtp`

## Performance
On  linux-amd64
```
BenchmarkTestifyNoThreatInBytes-4         500000              2628 ns/op               0 B/op          0 allocs/op
```

JSON Used
```json
{
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
```
### Create a verify
All the verifier Parameters are Optional

> Check Godoc for all option

Example Verify
```go
// with multiple config
	_, _ = New(WithMaxArrayElementCount(6),
		WithMaxContainerDepth(7),
		WithMaxObjectKeyLength(20), WithMaxStringLength(50),
		)

	// with single config
	_, _ = New(WithMaxStringLength(25))
```
### Errors

The JTP returns following error messages on Validation failure:

| Error Message                                                                                                                 |
|-------------------------------------------------------------------------------------------------------------------------|
| jtp.maxStringValueLengthReached.Max-[X]-Allowed.Found-[Y].                         |
| jtp.maxArrayElementCountReached.Max-[X]-Allowed.Found-[Y].                  |
| jtp.maxKeyLengthReached.Max-[X]-Allowed.Found-[Y] |
| jtp.maxContainerDepthReached.Max-[X]-Allowed.Found-[Y]           |
| jtp.maxObjectEntryCountReached.Max-[X]-Allowed.Found-[Y] |
| jtp.MalformedJSON | 

## Usage Example

```go
package main

import (
	"github.com/ankur-anand/gojtp"
	"log"
)

func main() {
	    json := _getTestJsonBytes()
	    verifier1, err := New(WithMaxArrayElementCount(6),
    		WithMaxContainerDepth(7),
    		WithMaxObjectKeyLength(20), WithMaxStringLength(50),
    		)
    	ok, err := verifier1.VerifyBytes(json)
    
    	verifier2, err := New(WithMaxStringLength(25))
    	ok, err = verifier2.VerifyBytes(json)
    	fmt.Println(ok, err)
}

func _getTestJsonBytes() []byte {
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
```

## Contact
Ankur Anand [@in_aanand](https://twitter.com/in_aanand)

## License
GOJTP source code is available under the MIT [License](/LICENSE).

Based on Parser from [tidwall](https://twitter.com/tidwall).