FROM alpine:3.12

RUN apk update && apk add tor

RUN mkdir -p /usr/local/tor
RUN mkdir -p /usr/local/tor/cus
RUN mkdir -p /usr/local/tor/rand
RUN mkdir -p /usr/local/tor/authorized_clients/
RUN chmod -R 700 /usr/local/tor

RUN mkdir -p /root/.tor
RUN chown -R root /root/.tor

COPY docker/tor/torrc /etc/tor/torrc

ARG password
RUN echo "HashedControlPassword $(tor --quiet --hash-password $password)" >> /etc/tor/torrc

# Client authorization
# Generate private key:
#   openssl genpkey -algorithm x25519 -out /tmp/k1.prv.pem
# Generate base64 private key:
#   cat /tmp/k1.prv.pem | grep -v " PRIVATE KEY" | base64pem -d | tail --bytes=32 | base32 | sed 's/=//g' > /tmp/k1.prv.key
# Generate base64 public key:
#   openssl pkey -in /tmp/k1.prv.pem -pubout | grep -v " PUBLIC KEY" | base64pem -d | tail --bytes=32 | base32 | sed 's/=//g' > /tmp/k1.pub.key

# Create file /usr/local/tor/authorized_clients/me.auth to look like:
# <auth-type>:<key-type>:<base32-encoded-public-key>
# Uncomment and replace with your base64 public key generated from the command above
# RUN echo "descriptor:x25519:S2MZ4JZDWDCR7OEYUDKUILIGLX24PDOCUPLNKJPFXQSLKPQUTIKQ" > /usr/local/tor/authorized_clients/me.auth
