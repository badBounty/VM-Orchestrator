FROM rabbitmq:3.8.9

ARG USER
ARG PASSWORD
ARG VHOST

WORKDIR /


RUN  apt-get update \
  && apt-get install -y wget\
  && apt-get install -y screen \
  && apt-get install -y dnsutils \
  && apt-get install -y nmap \
  && apt-get install -y git \
  && apt-get install -y python3-pip

RUN wget https://dl.google.com/go/go1.13.4.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.13.4.linux-amd64.tar.gz \
    && echo "PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc

ENV PATH "$PATH:/usr/local/go/bin"

RUN go get -u github.com/tomnomnom/httprobe


RUN mkdir VM-Orchestrator-project

WORKDIR /VM-Orchestrator-project

RUN mkdir VM-Orchestrator

ADD . /VM-Orchestrator-project/VM-Orchestrator

WORKDIR /VM-Orchestrator-project/VM-Orchestrator

RUN pip3 install -r requirements.txt
RUN pip3 install -r /VM-Orchestrator-project/VM-Orchestrator/VM_Orchestrator/VM_OrchestratorApp/src/scanning/tools/CORScanner/requirements.txt


WORKDIR /VM-Orchestrator-project

ENV USER ${USER}
ENV PASSWORD ${PASSWORD}
ENV VHOST ${VHOST}

EXPOSE 3000

WORKDIR /VM-Orchestrator-project/VM-Orchestrator/VM_Orchestrator

ADD init.sh /VM-Orchestrator-project/VM-Orchestrator/VM_Orchestrator/init.sh

CMD ["/VM-Orchestrator-project/VM-Orchestrator/VM_Orchestrator/init.sh"]

