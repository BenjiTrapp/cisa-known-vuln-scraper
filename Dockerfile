FROM alpine

LABEL "com.github.actions.name"="cisa-kev-analyzer"
LABEL "com.github.actions.description"="Automated analysis of CISA KEV"
LABEL "com.github.actions.icon"="cloud-lightning"
LABEL "com.github.actions.color"="Red"
LABEL "maintainer"="BenjiTrapp <nyctophobia@protonmail.com>"

# Install python/pip
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

# Install other dependencies & cleanup
RUN apk add bash curl git wget jq github-cli --no-cache && \
    rm -f /var/cache/apk/* 

COPY containerfiles/entrypoint.sh .
COPY containerfiles/cisa-kev-analyzer.py .

RUN chmod ugo+x entrypoint.sh

ENTRYPOINT ["bash entrypoint.sh"]