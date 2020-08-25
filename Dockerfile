FROM circleci/golang:1.14

RUN mkdir -p /go/src/github.com/dollarshaveclub/pvc
ADD . /go/src/github.com/dollarshaveclub/pvc

WORKDIR /go/src/github.com/dollarshaveclub/pvc
RUN go build


ENTRYPOINT ["echo", "hi from entrypoint"]
CMD ["echo 'hi from pvc'"]