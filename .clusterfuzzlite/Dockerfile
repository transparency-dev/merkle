# https://google.github.io/clusterfuzzlite/build-integration/#dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:37d560af1d31ae8d339902acaedb8eb6fdf3f04469706f39e3bbea44fa3fdeec
COPY . $SRC/merkle
WORKDIR $SRC/merkle
COPY .clusterfuzzlite/build.sh $SRC/
