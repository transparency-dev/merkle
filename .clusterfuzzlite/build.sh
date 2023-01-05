# https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/#buildsh
# undocumented dependency
go install github.com/AdamKorcz/go-118-fuzz-build@c5484365413eb6c532d2dbd0d16b553988ce6852
go get github.com/AdamKorcz/go-118-fuzz-build/testing@c5484365413eb6c532d2dbd0d16b553988ce6852

# workaround https://github.com/AdamKorcz/go-118-fuzz-build/issues/2
mv testonly/constants.go        testonly/constants_fuzz.go
mv testonly/reference_test.go   testonly/reference_test_fuzz.go
mv testonly/tree_test.go        testonly/tree_test_fuzz.go
mv testonly/tree.go             testonly/tree_fuzz.go

# necessary to list each fuzz test explicitly
compile_native_go_fuzzer github.com/transparency-dev/merkle/compact FuzzRangeNodes FuzzRangeNodes
compile_native_go_fuzzer github.com/transparency-dev/merkle/testonly FuzzConsistencyProofAndVerify FuzzConsistencyProofAndVerify
compile_native_go_fuzzer github.com/transparency-dev/merkle/testonly FuzzInclusionProofAndVerify FuzzInclusionProofAndVerify
compile_native_go_fuzzer github.com/transparency-dev/merkle/testonly FuzzHashAtAgainstReferenceImplementation FuzzHashAtAgainstReferenceImplementation
compile_native_go_fuzzer github.com/transparency-dev/merkle/testonly FuzzInclusionProofAgainstReferenceImplementation FuzzInclusionProofAgainstReferenceImplementation
compile_native_go_fuzzer github.com/transparency-dev/merkle/testonly FuzzConsistencyProofAgainstReferenceImplementation FuzzConsistencyProofAgainstReferenceImplementation
