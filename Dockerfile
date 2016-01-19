FROM golang:1.5.3

ENV GOPATH /go

COPY . /go/src/github.com/nutmegdevelopment/nutcracker

RUN cd /go/src/github.com/nutmegdevelopment/nutcracker && go get -d ./... && go test

RUN cd /go/src/github.com/nutmegdevelopment/nutcracker && go build -o /go/bin/nutcracker

CMD /go/bin/nutcracker
