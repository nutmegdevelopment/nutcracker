FROM golang:1.5.3

ENV GOPATH /go

RUN go get github.com/nutmegdevelopment/nutcracker

CMD /go/bin/nutcracker
