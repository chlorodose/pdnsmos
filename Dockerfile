FROM docker.io/library/rust:slim as builder-rs
COPY src /work/src
COPY Cargo.toml Cargo.lock /work/
WORKDIR /work
RUN cargo build --release --target-dir .

FROM docker.io/library/golang as builder-go
COPY nftsetd /work
WORKDIR /work
RUN go build .

FROM ghcr.io/sagernet/sing-box as sing-box
RUN apk add --no-cache wget jq && mkdir -p /work
WORKDIR /work

FROM sing-box as downloader
ARG dateday
RUN wget https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db && \
    wget https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db

FROM sing-box as exporter
COPY --from=downloader /work/*.db /work/
RUN set -euo pipefail && mkdir -p /geoip && \
    for TAG in $(sing-box geoip list); do \
        echo "Unpacking $TAG" && \
        sing-box geoip export "$TAG" -o /dev/stdout | jq -r '.rules.[0].ip_cidr | if type == "array" then .[] else . end' >"/geoip/$TAG.txt" \
    ; done
RUN set -euo pipefail && mkdir -p /geosite && \
    for TAG in $(sing-box geosite list | cut -d '(' -f 1); do \
        echo "Unpacking $TAG" && \
        sing-box geosite export "$TAG" -o /dev/stdout | jq -r '[ (.rules.[0].domain | [ . ] | flatten | map("full:"+.)), (.rules.[0].domain_suffix | [ . ] | flatten | map("domain:"+.)), (.rules.[0].domain_regex | [ . ] | flatten | map("regexp:"+.))] | add | .[]' >"/geosite/$TAG.txt" \
    ; done

FROM docker.io/powerdns/dnsdist-21
USER root
RUN mkdir -p /app/c /app/lua
WORKDIR /app
COPY --from=exporter /geoip /geoip
COPY --from=exporter /geosite /geosite

COPY --from=builder-rs /work/release/*.so /app/c/
COPY --from=builder-go /work/nftsetd /app/nftsetd
COPY lua/*.lua /app/lua/

COPY entry.sh /entry.sh
VOLUME ["/work"]
ENTRYPOINT [ "/entry.sh" ]
