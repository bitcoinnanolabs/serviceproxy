FROM rust:alpine3.17 AS builder


# Set the environment variables for pkg-config
ENV PKG_CONFIG_SYSROOT_DIR=/usr/lib
ENV PKG_CONFIG_LIBDIR=/usr/lib/pkgconfig
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include
# Instale as dependências necessárias, incluindo o pacote libstdc++.
RUN apk add --no-cache g++ libstdc++ musl-dev zeromq-dev pkgconfig openssl-dev


WORKDIR /app

COPY ./ .

# Adicione a configuração ao arquivo cargo/config.toml
RUN mkdir -p .cargo && \
    echo '[target.x86_64-unknown-linux-musl]' >> .cargo/config.toml && \
    echo 'rustflags = ["-C", "target-feature=-crt-static"]' >> .cargo/config.toml

RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl


####################################################################################################
## Final image
####################################################################################################
FROM alpine:3.17


WORKDIR /code

# Install runtime dependencies for ZeroMQ
RUN apk add --no-cache libzmq

# Copy our build
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/serviceproxy /usr/local/bin/

CMD ["/usr/local/bin/serviceproxy"]
