FROM python@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m pip install --no-cache-dir jupyterlab==4.5.9 \
    && useradd --create-home --uid 1000 --shell /bin/sh workspace \
    && passwd --delete workspace

COPY nvidia-smi /usr/local/bin/nvidia-smi

RUN chmod 0755 /usr/local/bin/nvidia-smi

USER workspace
