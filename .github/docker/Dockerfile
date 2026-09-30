# Build with scripts/build-fingerprint-image.sh; context contains verified release assets.
FROM gcr.io/distroless/static@sha256:58133991db06659feaabe0f4e97a35cebf15ef4ea08f8a4c6d2ee5f75e4aa6a0
ARG SOURCE_REPOSITORY=https://github.com/U1F357/Xray-core
ARG SOURCE_REVISION
ARG VERSION
LABEL org.opencontainers.image.title="xrui" \
      org.opencontainers.image.source=$SOURCE_REPOSITORY \
      org.opencontainers.image.revision=$SOURCE_REVISION \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.description="Xray fork with TCP fingerprint profiles and trusted VLESS propagation"
COPY xrui /usr/local/bin/xrui
COPY geodata/ /usr/local/share/xray/
COPY licenses/ /usr/share/licenses/xrui/
COPY config/ /usr/local/etc/xrui/
# Automatic fingerprint networking requires root plus explicitly granted NET_ADMIN/TUN.
USER 0:0
ENV TZ=Etc/UTC
ENTRYPOINT ["/usr/local/bin/xrui"]
CMD ["run", "-confdir", "/usr/local/etc/xrui/"]
