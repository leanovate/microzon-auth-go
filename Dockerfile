FROM busybox

ADD ./bin/microzon-auth /opt/

EXPOSE 8080

CMD ["/opt/microzon-auth", "server"]
