# https://google.github.io/clusterfuzzlite/build-integration/#dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:c7f01a616db0fc554d98edbd7d49a7177197f77fd4e1371bcb7774d7eac8216d
COPY . $SRC/merkle
WORKDIR $SRC/merkle
COPY .clusterfuzzlite/build.sh $SRC/
