# Himalayas mock CRM

A real, queryable HTTP service. "Mock" only means the company is fictional.
Connections and data flow are real: Everest fetches this exactly like a real
CRM.

## Run

```bash
pip install flask flask-cors
python3 apps/crm/crm_server.py
```

Serves `http://localhost:8787`.

## Endpoints

- `GET /accounts`
- `GET /accounts/<id>`
- `GET /accounts/by-domain/<domain>`
- `GET /support-engineers`
- `GET /support-engineers/match?focus=ios&label=locale`
- `GET /health`

## Add or change cases

Edit `customers.json` only, then restart the CRM process.
