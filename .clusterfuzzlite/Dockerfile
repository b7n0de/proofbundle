# ClusterFuzzLite build image (WP-D). Docs: https://google.github.io/clusterfuzzlite/
FROM gcr.io/oss-fuzz-base/base-builder-python

RUN pip3 install --no-cache-dir atheris

COPY . $SRC/proofbundle
WORKDIR $SRC/proofbundle
ENV SRC=$SRC/proofbundle
COPY .clusterfuzzlite/build.sh $SRC/build.sh
