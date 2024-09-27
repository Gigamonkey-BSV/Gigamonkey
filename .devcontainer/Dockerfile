FROM gigamonkey/gigamonkey-base-dev:v1.1.3

ADD https://api.github.com/repos/DanielKrawisz/data/git/refs/heads/master /root/data_version.json
RUN git clone --depth 1 --branch master https://github.com/DanielKrawisz/data.git /tmp/data
RUN cmake -B /tmp/data/build -S /tmp/data -DPACKAGE_TESTS=OFF
RUN cmake --build /tmp/data/build
RUN cmake --install /tmp/data/build
