FROM python:3.12-slim-bookworm

WORKDIR /tools

RUN apt-get update && apt-get install -y libgcrypt20 libglib2.0-0 libpixman-1-0 libsdl2-2.0-0 \
    libslirp0 git wget flex bison gperf cmake ninja-build ccache\
    libffi-dev libssl-dev dfu-util libusb-1.0-0 socat\
    net-tools iproute2 iputils-ping netcat-openbsd iptables bind9-dnsutils curl isc-dhcp-client

RUN git clone -b v5.2.1 --recursive https://github.com/espressif/esp-idf.git && \
    cd esp-idf && ./install.sh esp32 && \
    echo '. /tools/esp-idf/export.sh' >> '/root/.bashrc' && \
    python3 /tools/esp-idf/tools/idf_tools.py install qemu-xtensa qemu-riscv32 && \
    bash -c '. /tools/esp-idf/export.sh; ln -s $(which qemu-system-xtensa) /usr/bin/qemu-system-xtensa'

ENV POETRY_VIRTUALENVS_CREATE=false

WORKDIR /tmp/pysim-sdk
COPY poetry.lock pyproject.toml .
RUN pip install poetry && poetry install --no-root

COPY docker-entrypoint.sh /entrypoint.sh

ENTRYPOINT ["sh", "/entrypoint.sh"]