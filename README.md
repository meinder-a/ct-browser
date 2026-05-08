# ct-browser

a quick way to watch the certificate transparency stream and search it without losing your mind

this setup hooks into certstream, dumps everything into clickhouse, and gives you a basic web ui to run regex queries against what's being seen

## how it works

- **certstream-server-go**: handles the actual connection to the ct logs
- **clickhouse**: stores the records - it's configured with a 30-day ttl so it doesn't eat your whole disk
- **fastapi app**: a small python service that consumes the websocket, buffers inserts, and serves the search page

## quick start

1. make sure you have docker and compose installed
2. spin it up:
   ```bash
   docker compose up -d --build
   ```
3. wait a few seconds for clickhouse to wake up and the app to start ingestion
4. open `http://localhost:8082` in your browser

## search

the search bar supports standard regex - because it's backed by clickhouse's `match()` function, it's pretty fast even with millions of records

## config

- `compose.yml`: change ports or passwords here
- `certstream-config.yaml`: tweak how the certstream server behaves
- `db/init.sql`: check the schema or change the 30-day ttl

## license

mit
