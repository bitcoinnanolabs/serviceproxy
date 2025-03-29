FROM rust:alpine3.19 AS builder


# Set the environment variables for pkg-config
ENV PKG_CONFIG_SYSROOT_DIR=/usr/lib
ENV PKG_CONFIG_LIBDIR=/usr/lib/pkgconfig
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include
# Instale as dependências necessárias, incluindo o pacote libstdc++.

RUN apk add --no-cache \
    g++ \
    zeromq-dev \
    gcompat \
    musl-dev \
    gcc \
    alpine-sdk \
    libstdc++ \
    openssl-dev \
    pkgconfig 


WORKDIR /app

COPY ./ .

# Configure cargo for musl target and use rust-lld linker
RUN mkdir -p .cargo && \
    echo '[target.x86_64-unknown-linux-musl]' >> .cargo/config.toml && \
    echo 'rustflags = ["-C", "target-feature=-crt-static", "-C", "linker=rust-lld"]' >> .cargo/config.toml


RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl


####################################################################################################
## Final image
####################################################################################################
FROM alpine:3.19


WORKDIR /code

# Install runtime dependencies for ZeroMQ
RUN apk add --no-cache libzmq

# Copy our build
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/serviceproxy /usr/local/bin/

CMD ["/usr/local/bin/serviceproxy"]
