FROM openjdk:11-jre-slim

ARG EK_VERSION=7.10.2

ENV EKVERSION ${EK_VERSION}

RUN apt-get update -qq >/dev/null 2>&1 \
 && apt-get install wget sudo -qqy >/dev/null 2>&1 \
 && useradd -m -s /bin/bash elasticsearch \
 && echo elasticsearch ALL=NOPASSWD: ALL >/etc/sudoers.d/elasticsearch \
 && chmod 440 /etc/sudoers.d/elasticsearch

USER elasticsearch

WORKDIR /home/elasticsearch

RUN wget -q -O - https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${EK_VERSION}-linux-x86_64.tar.gz | tar -zx \
 && mkdir -p elasticsearch-${EK_VERSION}/data \
 && wget -q -O - https://artifacts.elastic.co/downloads/kibana/kibana-${EK_VERSION}-linux-x86_64.tar.gz | tar -zx

CMD elasticsearch-${EKVERSION}/bin/elasticsearch -E http.host=0.0.0.0 --quiet & kibana-${EKVERSION}-linux-x86_64/bin/kibana --allow-root --host 0.0.0.0 -Q

EXPOSE 9200 5601
