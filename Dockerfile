FROM alpine:latest as build-env

RUN apk update && apk --no-cache add build-base
WORKDIR /app
COPY src /app/src
RUN g++ src/*.cpp -o server -lpthread -lm

FROM alpine:latest
RUN apk update && apk add --no-cache libstdc++
COPY --from=build-env /app/server /app/server
WORKDIR /app
CMD ["/app/server"]

EXPOSE 28314