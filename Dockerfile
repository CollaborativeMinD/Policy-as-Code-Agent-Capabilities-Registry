# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE} AS interpreter
ARG PYTHON_APK
RUN if [ -n "$PYTHON_APK" ]; then apk add --no-cache "python-3.13=$PYTHON_APK" libstdc++; fi

FROM interpreter AS build
RUN python -m venv /build-tools
ENV PATH="/build-tools/bin:$PATH"
WORKDIR /src
COPY . .
RUN python -m pip install --no-cache-dir -r requirements-build.lock \
    && python -m build --wheel --no-isolation --outdir /dist
RUN python -m venv --without-pip /opt/venv \
    && python -m pip --python /opt/venv/bin/python install --no-cache-dir -r requirements.lock \
    && python -m pip --python /opt/venv/bin/python install --no-index --no-deps /dist/*.whl
ARG SOVEREIGN_SHA256
RUN --mount=type=secret,id=sovereign,target=/tmp/hmt_mcp_plus_server_kernel-1.0.0-py3-none-any.whl \
    if test -n "$SOVEREIGN_SHA256"; then \
      test "$SOVEREIGN_SHA256" = '19f4e7e02c3f1b53aeb99d65bfbf8c076e2b20725fec5488e11313731d04a206' \
      && echo "$SOVEREIGN_SHA256  /tmp/hmt_mcp_plus_server_kernel-1.0.0-py3-none-any.whl" | sha256sum -c - \
      && python -m pip --python /opt/venv/bin/python install --no-index --no-deps /tmp/hmt_mcp_plus_server_kernel-1.0.0-py3-none-any.whl; \
    fi
RUN python -m pip --python /opt/venv/bin/python check

FROM interpreter AS runtime
ARG SERVICE_UID
ARG SERVICE_GID
ARG REVISION
LABEL org.opencontainers.image.revision="$REVISION"
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY --from=build /opt/venv /opt/venv
RUN mkdir -p /state && touch /state/.volume-initialized && chmod 0700 /state && chown -R "$SERVICE_UID:$SERVICE_GID" /state
WORKDIR /state
USER ${SERVICE_UID}:${SERVICE_GID}
ENTRYPOINT ["hmt-capability-server"]
