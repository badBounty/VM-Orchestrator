docker image build -t elastic-vm .
docker run -d --name elastic-vm -p 9200:9200 -p 5601:5601 elastic-vm
sleep 1m
docker cp elastic-vm:/home/elasticsearch/kibana-7.10.2-linux-x86_64/config/certs/elasticsearch-ca.pem ./elasticsearch-ca.pem