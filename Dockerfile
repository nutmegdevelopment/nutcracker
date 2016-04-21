FROM frolvlad/alpine-glibc

COPY etc /etc
ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/cacert.pem
COPY nutcracker /nutcracker

CMD [ "/nutcracker" ]
ENTRYPOINT [ "/nutcracker" ]