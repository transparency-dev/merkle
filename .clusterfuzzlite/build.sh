# https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/#buildsh
# undocumented dependency
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/utils
# necessary to list each fuzz test explicitly
compile_native_go_fuzzer github.com/transparency-dev/merkle/compact FuzzRangeNodes FuzzRangeNodes
