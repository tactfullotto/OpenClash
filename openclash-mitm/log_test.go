package main

import (
	"testing"
	"time"
)

func TestParseOpenWRTTZ(t *testing.T) {
	cases := []struct {
		in      string
		wantSec int
	}{
		{"CST-8", 8 * 3600},
		{"HKT-8", 8 * 3600},
		{"EST5", -5 * 3600},
		{"UTC", 0},
	}
	for _, tc := range cases {
		loc := parseOpenWRTTZ(tc.in)
		if tc.in == "UTC" {
			if loc != nil {
				t.Fatalf("UTC => nil, got %v", loc)
			}
			continue
		}
		if loc == nil {
			t.Fatalf("%q => nil", tc.in)
		}
		_, off := time.Now().In(loc).Zone()
		if off != tc.wantSec {
			t.Fatalf("%q offset=%d want %d", tc.in, off, tc.wantSec)
		}
	}
}
