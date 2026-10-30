package cveidx

import "testing"

func TestSplitProductVersion(t *testing.T) {
	cases := []struct{ input, product, version string }{
		{"thinkphp 8.0.3", "thinkphp", "8.0.3"},
		{"ThinkPHP 6", "ThinkPHP", "6"},
		{"Apache HTTP Server v2.4.49", "Apache HTTP Server", "v2.4.49"},
		{"nginx 1.24.0-1", "nginx", "1.24.0-1"},
		{"  PHP\t8.1.29  ", "PHP", "8.1.29"},
		{"http2", "http2", ""},
		{"log4j", "log4j", ""},
		{"thinkphp6", "thinkphp6", ""},
		{"baota panel", "baota panel", ""},
		{"Next.js App", "Next.js App", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			p, v := SplitProductVersion(tc.input)
			if p != tc.product || v != tc.version {
				t.Fatalf("got (%q,%q),want (%q,%q)", p, v, tc.product, tc.version)
			}
		})
	}
}

func TestSearchProductVersionPreservesCandidateSet(t *testing.T) {
	idx, err := Load(fixtureDir(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ plain, versioned string }{
		{"apache", "apache 2.4.49"}, {"http server", "http server v2.4.49"},
		{"php", "PHP 8.1.29"}, {"nginx", "nginx 1.24.0-1"},
	} {
		t.Run(tc.versioned, func(t *testing.T) {
			plain := idx.Search(SearchOpts{Product: tc.plain, Limit: 10})
			got := idx.Search(SearchOpts{Product: tc.versioned, Limit: 10})
			if len(got) != len(plain) || len(got) == 0 {
				t.Fatalf("versioned candidates=%d plain=%d", len(got), len(plain))
			}
			for i := range plain {
				if got[i].TemplateID != plain[i].TemplateID {
					t.Fatalf("candidate order changed: %v != %v", got, plain)
				}
			}
		})
	}
	if got := idx.Search(SearchOpts{Product: "not-a-known-product 8.1.29"}); len(got) != 0 {
		t.Fatalf("unknown product matched %d", len(got))
	}
	if got := idx.Search(SearchOpts{Product: "apache 2.4.49", MinCVSS: 9}); len(got) != 0 {
		t.Fatal("version split bypassed CVSS filter")
	}
	if got := idx.Search(SearchOpts{Product: "nginx 1.24.0", Verified: true}); len(got) != 0 {
		t.Fatal("version split bypassed verified filter")
	}
	if _, ok := idx.LookupCVE("CVE-2021-41773"); !ok {
		t.Fatal("exact CVE lookup changed")
	}
}
