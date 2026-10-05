FROM rust:1.79-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release
FROM debian:bookworm-slim
COPY --from=build /src/target/release/* /usr/local/bin/app
ENV INFRAI_API_KEY=""
ENTRYPOINT ["app"]
