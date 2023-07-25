FROM archlinux:latest AS base

# Update package database and install required dependencies
RUN pacman -Sy --noconfirm && \
    pacman -S --noconfirm sagemath


FROM rust:latest AS build
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM archlinux:latest

# Update package database and install required dependencies
RUN pacman -Sy --noconfirm && \
    pacman -S --noconfirm sagemath

COPY --from=build /usr/src/app/target/release/precomputations_server /usr/local/bin/

WORKDIR /usr/local/bin

EXPOSE 8080

CMD ["precomputations_server"]