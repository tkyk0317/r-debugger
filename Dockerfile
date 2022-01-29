FROM rust:1.57-slim-bullseye

RUN apt-get update && \
    apt-get install -y make \
    g++ && \
    apt-get autoremove
RUN rustup component add clippy
RUN rustup component add rustfmt
RUN rustup component add rust-analysis
RUN rustup component add rust-src
RUN rustup component add rls

WORKDIR /app

# for crate cache
RUN mkdir -p ./src/ && \
    echo "fn main() {}" > ./src/main.rs
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
RUN cargo fetch

COPY ./src/ ./src
COPY ./sample/ ./sample

RUN cd sample && make