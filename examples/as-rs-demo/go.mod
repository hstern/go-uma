module github.com/hstern/go-uma/examples/as-rs-demo

go 1.26

require github.com/hstern/go-uma v0.0.0

// The example module is intentionally kept outside the library's own
// dependency graph so that consumers `go get`-ing the library do not
// pull in the example's transitive dependencies (today there are
// none, but the boundary is in place for the day there are). The
// replace directive below pins the require above to the in-repo copy
// of the library, so `go build ./...` from this directory works
// against unreleased changes and continues to work once v0.1.0 is
// tagged and published.
replace github.com/hstern/go-uma => ../..
