docker image build -t elastic-vm .
docker run -d --name elastic-vm -p 9200:9200 -p 5601:5601 elastic-vm