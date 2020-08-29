FROM nekosune/gigamonkey-bitcoin-sv-base:latest
LABEL maintainer="Katrina Knight <kat.knight@newgaea.net>"

WORKDIR /tmp/build/
COPY . /tmp/gigamonkey
RUN cmake \
        -DJOBS=${BUILD_JOBS} \
        -DBOOST_ROOT=/usr/bsv/ \
        -DCHAIN_SRC_ROOT=/tmp/bitcoin-sv-1.0.4/ \
        -DCHAIN_EXTRA_FLAGS=--with-boost=/usr/bsv \
        -DCMAKE_INSTALL_PREFIX=/usr/bsv/ \
        -DCMAKE_PREFIX_PATH=/usr/bsv/ \
        /tmp/gigamonkey
RUN make
CMD ["ctest -E \"(autocompact_test)|(corruption_test)|(db_test)|(dbformat_test)\""]