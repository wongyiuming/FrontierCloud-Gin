# Development-only OCI layout fixture; never a runnable product image.
FROM scratch
ARG REVISION
LABEL frontiercloud.revision=$REVISION frontiercloud.component="web" \
      frontiercloud.runtime="go" frontiercloud.schema-generation="3" \
      frontiercloud.release-manifest-version="1" \
      org.opencontainers.image.source="https://github.com/wongyiuming/FrontierCloud-Gin" \
      org.opencontainers.image.revision=$REVISION
COPY README.md /format-fixture.txt
