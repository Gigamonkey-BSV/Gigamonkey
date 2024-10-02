FROM gigamonkey/gigamonkey-base-dev:v1.1.4

ADD https://api.github.com/repos/DanielKrawisz/data/git/refs/heads/master /root/data_version.json
RUN git clone --depth 1 --branch master https://github.com/DanielKrawisz/data.git /tmp/data
RUN cmake -G Ninja -B /tmp/data/build -S /tmp/data -DPACKAGE_TESTS=OFF
RUN cmake --build /tmp/data/build -j 4
RUN cmake --install /tmp/data/build
