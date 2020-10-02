docker run -d --name postgres-vm -e POSTGRES_PASSWORD=secret -e POSTGRES_USER=redmine -p 5432:5432 postgres
echo 'Waiting a few seconds for postgres to start'
sleep 5
docker run -d --name redmine-vm -e REDMINE_DB_POSTGRES=postgres-vm -e REDMINE_DB_USERNAME=redmine -e REDMINE_DB_PASSWORD=secret -p 3000:3000 --link postgres-vm:postgres redmine
docker cp redmine_inserts.sql postgres-vm:/tmp/redmine_inserts.sql
docker exec -it postgres-vm psql -U redmine -d redmine -a -f /tmp/redmine_inserts.sql

