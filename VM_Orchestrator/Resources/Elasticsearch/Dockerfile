FROM openjdk:11-jre-slim

ARG EK_VERSION=7.10.2

ENV EKVERSION ${EK_VERSION}
ENV ES_HOME /home/elasticsearch/elasticsearch-${EK_VERSION}/
ENV ESW_PATH_CONF /home/elasticsearch/elasticsearch-${EK_VERSION}/config
ENV KIBANA_HOME /home/elasticsearch/kibana-${EKVERSION}-linux-x86_64/
ENV KIBANA_PATH_CONF /home/elasticsearch/kibana-${EKVERSION}-linux-x86_64/config

RUN apt-get update -qq >/dev/null 2>&1 \
 && apt-get install wget sudo -qqy >/dev/null 2>&1 \
 && useradd -m -s /bin/bash elasticsearch \
 && echo elasticsearch ALL=NOPASSWD: ALL >/etc/sudoers.d/elasticsearch \
 && chmod 440 /etc/sudoers.d/elasticsearch


RUN apt-get install -y expect
RUN apt-get install -y unzip
RUN apt-get install -y screen

USER elasticsearch

WORKDIR /home/elasticsearch

RUN wget -q -O - https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${EK_VERSION}-linux-x86_64.tar.gz | tar -zx \
 && mkdir -p elasticsearch-${EK_VERSION}/data \
 && wget -q -O - https://artifacts.elastic.co/downloads/kibana/kibana-${EK_VERSION}-linux-x86_64.tar.gz | tar -zx


ADD ConfigHTTPs.sh /home/elasticsearch/ConfigHTTPs.sh

WORKDIR /home/elasticsearch/elasticsearch-${EK_VERSION}


RUN mkdir ./config/certs
RUN ./bin/elasticsearch-certutil ca --silent --out ./config/certs/elastic-stack-ca.p12 --pass ""
RUN ./bin/elasticsearch-certutil cert --ca ./config/certs/elastic-stack-ca.p12 --ca-pass "" --silent --out ./config/certs/elastic-certificates.p12 --pass ""
RUN ./bin/elasticsearch-certutil cert -name kibana-server -dns localhost,127.0.0.1 --out /home/elasticsearch/elasticsearch-${EK_VERSION}/config/certs/kibana-server.p12 --pass ""
RUN /home/elasticsearch/ConfigHTTPs.sh
RUN unzip elasticsearch-ssl-http.zip
RUN cp elasticsearch/http.p12 config/certs/
RUN echo "xpack.security.enabled: true" >> config/elasticsearch.yml
RUN echo "xpack.security.transport.ssl.enabled: true" >> config/elasticsearch.yml
RUN echo "xpack.security.transport.ssl.verification_mode: certificate" >> config/elasticsearch.yml
RUN echo "xpack.security.transport.ssl.keystore.path: /home/elasticsearch/elasticsearch-7.10.2/config/certs/elastic-certificates.p12" >> config/elasticsearch.yml
RUN echo "xpack.security.transport.ssl.truststore.path: /home/elasticsearch/elasticsearch-7.10.2/config/certs/elastic-certificates.p12" >> config/elasticsearch.yml
RUN echo "xpack.security.http.ssl.enabled: true" >> config/elasticsearch.yml
RUN echo 'xpack.security.http.ssl.keystore.path: "/home/elasticsearch/elasticsearch-7.10.2/config/certs/http.p12"' >> config/elasticsearch.yml

WORKDIR /home/elasticsearch/kibana-${EK_VERSION}-linux-x86_64

RUN  mkdir ./config/certs
RUN cp /home/elasticsearch/elasticsearch-${EK_VERSION}/kibana/elasticsearch-ca.pem config/certs
RUN cp /home/elasticsearch/elasticsearch-${EK_VERSION}/config/certs/kibana-server.p12 config/certs

RUN echo 'elasticsearch.username: "elastic"' >> config/kibana.yml
RUN echo 'elasticsearch.password: "elastic"' >> config/kibana.yml
RUN echo 'elasticsearch.hosts: [https://localhost:9200]' >> config/kibana.yml
RUN echo 'elasticsearch.ssl.certificateAuthorities: [ "/home/elasticsearch/kibana-7.10.2-linux-x86_64/config/certs/elasticsearch-ca.pem" ]' >> config/kibana.yml
RUN echo 'elasticsearch.ssl.verificationMode: certificate' >> config/kibana.yml
RUN echo "server.ssl.enabled: true" >> config/kibana.yml
RUN echo 'server.ssl.keystore.path: "/home/elasticsearch/kibana-7.10.2-linux-x86_64/config/certs/kibana-server.p12"' >> config/kibana.yml

WORKDIR /home/elasticsearch/

ADD ConfigPasswords.sh /home/elasticsearch/ConfigPasswords.sh

RUN /home/elasticsearch/elasticsearch-${EK_VERSION}/bin/elasticsearch-keystore create
RUN /home/elasticsearch/kibana-${EK_VERSION}-linux-x86_64/bin/kibana-keystore create 
RUN echo "" | /home/elasticsearch/kibana-${EK_VERSION}-linux-x86_64/bin/kibana-keystore add server.ssl.keystore.password
RUN elasticsearch-${EKVERSION}/bin/elasticsearch -E http.host=0.0.0.0 --quiet & (sleep 2m; /home/elasticsearch/ConfigPasswords.sh)


CMD elasticsearch-${EKVERSION}/bin/elasticsearch -E http.host=0.0.0.0 & kibana-${EKVERSION}-linux-x86_64/bin/kibana --allow-root --host 0.0.0.0 -Q --log-file ${KIBANA_HOME}/logfile.log

EXPOSE 9200 5601
