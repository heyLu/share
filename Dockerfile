FROM docker.io/golang:1.23-alpine3.21 as builder

WORKDIR /build

COPY . .
RUN go build .

FROM alpine:3.21

RUN apk add --no-cache shadow && useradd --home-dir /dev/null --shell /bin/false share && apk del shadow

RUN mkdir /uploads && chown share:share /uploads
VOLUME /uploads

USER share

WORKDIR /app

CMD /app/share -addr 0.0.0.0:9999 -uploads-dir /uploads

COPY --from=builder /build/share /app/
