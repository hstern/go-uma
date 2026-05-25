# go-uma examples

Runnable example programs that exercise the `go-uma` library end-to-
end. Each subdirectory is its own Go module — they sit outside the
library's own dependency graph so consumers `go get`-ing the library
do not transitively depend on anything an example pulls in.

| Example                       | Demonstrates                                                                                                                                                                                                                                                                                                                       |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`as-rs-demo`](as-rs-demo/)   | A single binary that brings up an in-process Authorization Server and Resource Server, registers a resource set, then drives the full UMA 2.0 flow as a requesting-party client: 401 challenge → permission ticket → `/token` redemption → RPT → introspection. The README walks through each wire interaction. |

## Running an example

From the example's directory:

```sh
cd examples/as-rs-demo
go run .
```

Each example's `go.mod` declares the example as a separate module and
uses a `replace` directive to pin its `github.com/hstern/go-uma`
dependency to the in-repo copy of the library at `../..`. That means
the examples build and run against unreleased library changes without
any extra setup, and continue to work once the library is published.

The library itself ships with zero non-test runtime dependencies. The
separate-module layout preserves that property regardless of what an
example needs.
