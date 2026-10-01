package main

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// AWS Signature Version 4 examples from the Amazon S3 API reference ("Examples:
// Signature Calculations in AWS Signature Version 4", header-based auth). If these
// match, requests are signed exactly as AWS S3 and S3-compatible stores verify them.
func TestSigV4AgainstAWSExamples(t *testing.T) {
	when := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	newClient := func() *s3Client {
		c, err := newS3Client(Device{Host: "https://s3.amazonaws.com", Username: "AKIAIOSFODNN7EXAMPLE",
			Secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Options: `{"region":"us-east-1","path_style":false}`})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cases := []struct {
		name, key string
		query     url.Values
		hdr       map[string]string
		wantSig   string
		wantHdrs  string
	}{
		{"GET object with range", "test.txt", nil, map[string]string{"range": "bytes=0-9"},
			"f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", "host;range;x-amz-content-sha256;x-amz-date"},
		{"GET bucket lifecycle", "", url.Values{"lifecycle": {""}}, nil,
			"fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", "host;x-amz-content-sha256;x-amz-date"},
		{"GET bucket list objects", "", url.Values{"max-keys": {"2"}, "prefix": {"J"}}, nil,
			"34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7", "host;x-amz-content-sha256;x-amz-date"},
	}
	for _, c := range cases {
		req, err := newClient().signed("GET", "examplebucket", c.key, c.query, c.hdr, when)
		if err != nil {
			t.Fatal(err)
		}
		auth := req.Header.Get("Authorization")
		if !strings.Contains(auth, "Signature="+c.wantSig) || !strings.Contains(auth, "SignedHeaders="+c.wantHdrs) ||
			!strings.Contains(auth, "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request") {
			t.Errorf("%s: signature differs from AWS's published example\n got: %s", c.name, auth)
		}
	}
}
