import json
import os

from flask import Flask, abort, jsonify, request
from flask_cors import CORS


DATA = os.path.join(os.path.dirname(__file__), "customers.json")


def load():
    with open(DATA, encoding="utf-8") as f:
        return json.load(f)


app = Flask(__name__)
CORS(app)


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "himalayas-crm"})


@app.get("/accounts")
def accounts():
    db = load()
    summary = [
        {k: a[k] for k in ("id", "name", "domain", "plan", "arr_usd", "region", "managed")}
        for a in db["accounts"]
    ]
    return jsonify({"count": len(summary), "accounts": summary})


@app.get("/accounts/<acc_id>")
def account(acc_id):
    db = load()
    for account_item in db["accounts"]:
        if account_item["id"] == acc_id:
            return jsonify(account_item)
    abort(404, description=f"no account {acc_id}")


@app.get("/accounts/by-domain/<domain>")
def by_domain(domain):
    db = load()
    normalized_domain = domain.lower().strip()
    for account_item in db["accounts"]:
        if account_item["domain"].lower() == normalized_domain:
            return jsonify(account_item)
    abort(404, description=f"no account for domain {normalized_domain}")


@app.get("/support-engineers")
def engineers():
    return jsonify(load()["support_engineers"])


@app.get("/support-engineers/match")
def match_engineer():
    focus = (request.args.get("focus") or "").lower()
    label = (request.args.get("label") or "").lower()
    engineers_list = load()["support_engineers"]
    best, best_score = None, -1

    for engineer in engineers_list:
        score = 0
        blob = (
            engineer["focus"]
            + " "
            + engineer["embedded_team"]
            + " "
            + " ".join(engineer.get("prior_fixes", []))
        ).lower()
        if focus and focus in blob:
            score += 2
        if focus == "android" and "mobile" in blob:
            score += 1
        if label and label in blob:
            score += 1
        if score > best_score:
            best, best_score = engineer, score

    return jsonify({"assignee": best, "score": best_score})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8787, debug=True)
