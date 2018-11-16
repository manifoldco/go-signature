module github.com/manifoldco/go-signature

require (
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/alecthomas/gometalinter v2.0.11+incompatible
	github.com/client9/misspell v0.3.4
	github.com/golang/lint v0.0.0-20181026193005-c67002cb31c3
	github.com/gordonklaus/ineffassign v0.0.0-20180909121442-1003c8bd00dc
	github.com/kr/pretty v0.1.0 // indirect
	github.com/manifoldco/go-base64 v1.0.1
	github.com/tsenart/deadcode v0.0.0-20160724212837-210d2dc333e9
	golang.org/x/crypto v0.0.0-20181112202954-3d3f9f413869
	golang.org/x/tools v0.0.0-20181115194243-f87c222f1487 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

// This version of kingpin is incompatible with the released version of
// gometalinter until the next release of gometalinter, and possibly until it
// has go module support, we'll need this exclude, and perhaps some more.
//
// After that point, we should be able to remove it.
exclude gopkg.in/alecthomas/kingpin.v3-unstable v3.0.0-20180810215634-df19058c872c
