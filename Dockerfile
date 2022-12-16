FROM docker.io/golang:1.19-alpine3.16 as builder

WORKDIR /build

COPY . .
RUN go build .

FROM alpine:3.16

RUN apk add --no-cache shadow && useradd --home-dir /dev/null --shell /bin/false share && apk del shadow
USER share

VOLUME /uploads

WORKDIR /app

CMD /app/share -addr 0.0.0.0:9999 -uploads-dir /uploads

COPY --from=builder /build/share /app/
