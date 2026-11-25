# Used by goreleaser (dockers_v2): the build context holds the prebuilt binary
# per platform under $TARGETPLATFORM/.
FROM --platform=$BUILDPLATFORM busybox:1.37 AS cache
RUN mkdir /cache

FROM scratch
ARG TARGETPLATFORM
COPY --from=cache --chown=65532:65532 /cache /cache
COPY $TARGETPLATFORM/sslcheck /sslcheck
ENV SSLCHECK_CACHE_DIR=/cache
VOLUME /cache
USER 65532:65532
ENTRYPOINT ["/sslcheck"]
