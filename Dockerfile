# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE} AS build
WORKDIR /src
COPY . .
RUN python -m pip install --no-cache-dir -r requirements-build.lock \
    && python -m build --wheel --no-isolation --outdir /dist
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-cache-dir -r requirements.lock \
    && /opt/venv/bin/python -m pip install --no-index --no-deps /dist/*.whl
ARG SOVEREIGN_SHA256
RUN --mount=type=secret,id=sovereign,target=/tmp/hmt_mcp_plus_server_kernel-1.0.0-py3-none-any.whl \
    if test -n "$SOVEREIGN_SHA256"; then \
      test "$SOVEREIGN_SHA256" = '19f4e7e02c3f1b53aeb99d65bfbf8c076e2b20725fec5488e11313731d04a206' \
      && echo "$SOVEREIGN_SHA256  /tmp/hmt_mcp_plus_server_kernel-1.0.0-py3-none-any.whl" | sha256sum -c - \
      && /opt/venv/bin/python -m pip install --no-index --no-deps /tmp/hmt_mcp_plus_server_kernel-1.0.0-py3-none-any.whl; \
    fi
RUN /opt/venv/bin/python -m pip check

FROM ${PYTHON_IMAGE} AS runtime
ARG SERVICE_UID
ARG SERVICE_GID
ARG REVISION
LABEL org.opencontainers.image.revision="$REVISION"
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY --from=build /opt/venv /opt/venv
RUN groupadd --gid "$SERVICE_GID" runtime \
    && useradd --uid "$SERVICE_UID" --gid "$SERVICE_GID" --no-create-home --shell /usr/sbin/nologin runtime \
    && install -d -m 0700 -o runtime -g runtime /state \
    && touch /state/.volume-initialized
WORKDIR /state
USER runtime:runtime
ENTRYPOINT ["hmt-capability-server"]
