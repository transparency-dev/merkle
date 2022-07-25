# https://google.github.io/clusterfuzzlite/build-integration/#dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-go
COPY . $SRC/merkle
WORKDIR $SRC/merkle
COPY .clusterfuzzlite/build.sh $SRC/
