FROM golang:1.16-buster as builder

ARG git_commit
ENV GIT_COMMIT=$git_commit

# for linters to avoid warnings. we won't use linters in Docker anyway
ENV LATEST_COMMIT="undefined"

#RUN apk --no-cache add make gcc g++ linux-headers git bash ca-certificates libgcc libstdc++

WORKDIR /app

# next 2 lines helping utilize docker cache
COPY go.mod go.sum ./
RUN go mod download

ADD . .
RUN make all

FROM debian:buster

#RUN apk add --no-cache ca-certificates libgcc libstdc++
COPY --from=builder /app/build/bin/* /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp 8080 9090 6060
