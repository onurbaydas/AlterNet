FROM rust:1.85.0 as builder

WORKDIR /usr/src/alternet
COPY . .

RUN cargo build --release --package alternet-daemon

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/alternet/target/release/alternet-daemon /usr/local/bin/alternet-daemon

EXPOSE 4001 4002

ENTRYPOINT ["alternet-daemon"]
