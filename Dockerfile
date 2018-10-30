FROM python:3.6.7-alpine3.6
ADD . /opt/app
WORKDIR /opt/app
RUN  apk --no-cache add libffi-dev openssl-dev build-base &&pip install -r *.txt &&apk del build-base && rm -rf ~/.cache/pip
CMD /bin/sh
