FROM frolvlad/alpine-glibc

RUN mkdir -p /etc/ssl/certs
ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/cacert.pem
ADD nutcracker /nutcracker

CMD [ "/nutcracker" ]
ENTRYPOINT [ "/nutcracker" ]