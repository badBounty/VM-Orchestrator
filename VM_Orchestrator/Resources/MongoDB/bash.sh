docker run -d --name mongo -p 27017:27017 mongo:4.0.20
echo 'Waiting a few seconds for mongo to start'
sleep 5
docker cp libraries_versions.json mongo:/tmp/libraries_versions.json
docker cp observations.json mongo:/tmp/observations.json
docker exec -it mongo mongoimport --db Project --collection observations --file /tmp/observations.json --jsonArray
docker exec -it mongo mongoimport --db Project --collection libraries_versions --file /tmp/libraries_versions.json --jsonArray