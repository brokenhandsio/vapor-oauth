FROM swift:5.7

WORKDIR /package

COPY . ./

RUN swift package --enable-prefetching fetch
RUN swift package clean
CMD swift test
