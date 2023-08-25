FROM golang:1.21.0-alpine3.18 as builder
WORKDIR /workspace/
ADD ./ /workspace/

ENV GO_PROXY="https://goproxy.cn,direct"

RUN go env -w GOPROXY=${GO_PROXY}
RUN go build main.go

FROM alpine:3.18.2

COPY --from=builder /workspace/main /workspace/sso_token_service
COPY config.yml /workspace/config.yml
WORKDIR /workspace

EXPOSE 10086

RUN chmod +x sso_token_service

# set timezone
RUN apk add -U tzdata && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && apk del tzdata

CMD ./sso_token_service 2>&1
