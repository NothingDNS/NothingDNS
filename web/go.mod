// This is a deliberate module boundary, not an accidental artifact.
//
// The React dashboard under web/ contains no Go source code, but
// web/node_modules/flatted ships a Go port (pkg/flatted/flatted.go).
// Without this go.mod, `go test ./...` and `go vet ./...` run from the
// repository root descend into web/node_modules/ and compile/test that
// third-party package, producing noise in CI output and inflating test
// wall-clock time.
//
// A nested go.mod makes web/ a separate module: Go's ./... pattern does
// not cross module boundaries, so the root module's tooling never enters
// web/ (or web/node_modules/). The dashboard's real toolchain is the
// npm/Vite/TypeScript stack declared in web/package.json.
module web

go 1.26.6
