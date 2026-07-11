ARG BASE_IMAGE=private.invalid/base
FROM ${BASE_IMAGE} AS build
ARG BUILD_TOKEN
ENV BUILD_MODE=release
FROM build AS runtime
ENV APP_MODE=production
