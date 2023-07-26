FROM rust:latest AS build
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM archlinux:latest

# Update package database and install required dependencies
RUN pacman -Sy --noconfirm && \
    pacman -S --noconfirm sagemath

RUN mkdir /crypto
RUN chmod 777 /crypto

COPY --from=build /usr/src/app/target/release/precomputations_server /usr/local/bin/
COPY --from=build /usr/src/app/precompute.sh /usr/local/bin/
COPY --from=build /usr/src/app/rm.sh /usr/local/bin/

WORKDIR /usr/local/bin

VOLUME ["/crypto"]

EXPOSE 8080

CMD ["precomputations_server"]