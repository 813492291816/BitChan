FROM alpine:latest

RUN apk update && apk add tor

COPY docker/tor/torrc /etc/tor/torrc
RUN chown -R tor /etc/tor

ARG password
RUN echo "HashedControlPassword $(tor --quiet --hash-password $password)" >> /etc/tor/torrc
