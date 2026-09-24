FROM golang:1.26.4-alpine3.23 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -o /out/shared-auth ./cmd/server \
    && CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -o /out/keygen ./cmd/keygen

FROM alpine:3.23
RUN apk add --no-cache ca-certificates wget \
    && addgroup -S app && adduser -S -G app app \
    && mkdir -p /keys && chown app:app /keys
WORKDIR /app
COPY --from=build /out/shared-auth /app/shared-auth
COPY --from=build /out/keygen /app/keygen
USER app
EXPOSE 18082
ENTRYPOINT ["/app/shared-auth"]
