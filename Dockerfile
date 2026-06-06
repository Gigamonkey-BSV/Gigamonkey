FROM gigamonkey/gigamonkey-base-dev:v2.3

ADD https://api.github.com/repos/DanielKrawisz/data/git/refs/heads/master /root/data_version.json
RUN git clone --depth 1 --branch master https://github.com/DanielKrawisz/data.git /tmp/data
RUN cmake -G Ninja -B /tmp/data/build -S /tmp/data -DPACKAGE_TESTS=OFF
RUN cmake --build /tmp/data/build -j 4
RUN cmake --install /tmp/data/build

ADD https://api.github.com/repos/DanielKrawisz/net/git/refs/heads/master /root/net_version.json
RUN git clone --depth 1 --branch master https://github.com/DanielKrawisz/net.git /tmp/net
RUN cmake -G Ninja -B /tmp/net/build -S /tmp/net -DPACKAGE_TESTS=OFF
RUN cmake --build /tmp/net/build -j 4
RUN cmake --install /tmp/net/build

WORKDIR /home/Gigamonkey
COPY . .
RUN cmake -G Ninja -B build -S . -DPACKAGE_TESTS=OFF
RUN cmake --build . -j 4
RUN cmake --install .
