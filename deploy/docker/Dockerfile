ARG TACHYON_BASE_IMAGE=debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
FROM ${TACHYON_BASE_IMAGE}
COPY --chown=65532:65532 --chmod=0555 bin/tachyon-core /opt/tachyon/tachyon-core
USER 65532:65532
ENTRYPOINT ["/opt/tachyon/tachyon-core"]
