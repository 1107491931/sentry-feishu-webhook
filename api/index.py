from flask import Flask, request, jsonify
import requests
import json
import os
import hmac
import hashlib

app = Flask(__name__)

FEISHU_WEBHOOK_URL = os.environ.get("FEISHU_WEBHOOK_URL", "")
SENTRY_CLIENT_SECRET = os.environ.get("SENTRY_CLIENT_SECRET", "")


def verify_sentry_signature(payload, signature):
    if not SENTRY_CLIENT_SECRET:
        return True
    expected = hmac.new(
        SENTRY_CLIENT_SECRET.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def build_feishu_card(data, resource, action):
    if resource == "issue" and action == "created":
        issue = data.get("data", {}).get("issue", {})
        title = issue.get("title", "Unknown Issue")
        culprit = issue.get("culprit", "")
        url = issue.get("url", "")
        project = data.get("data", {}).get("project", {}).get("name", "Unknown")
        release = issue.get("firstRelease", {})
        release_version = release.get("version", "Unknown") if release else "Unknown"
        level = issue.get("level", "error")
        first_seen = issue.get("firstSeen", "")
        level_color = "red" if level in ("error", "fatal") else "orange"

        return {
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {"tag": "plain_text", "content": f"Sentry New Issue [{level.upper()}]"},
                    "template": level_color,
                },
                "elements": [
                    {
                        "tag": "div",
                        "fields": [
                            {"is_short": True, "text": {"tag": "lark_md", "content": f"**Project:**\n{project}"}},
                            {"is_short": True, "text": {"tag": "lark_md", "content": f"**Level:**\n{level.upper()}"}},
                            {"is_short": True, "text": {"tag": "lark_md", "content": f"**Release:**\n{release_version}"}},
                            {"is_short": True, "text": {"tag": "lark_md", "content": f"**First Seen:**\n{first_seen}"}},
                        ],
                    },
                    {"tag": "div", "text": {"tag": "lark_md", "content": f"**Error:**\n{title}"}},
                    {"tag": "div", "text": {"tag": "lark_md", "content": f"**Location:**\n{culprit}"}},
                    {"tag": "hr"},
                    {
                        "tag": "action",
                        "actions": [
                            {
                                "tag": "button",
                                "text": {"tag": "plain_text", "content": "View in Sentry"},
                                "url": url,
                                "type": "primary",
                            }
                        ],
                    },
                ],
            },
        }

    return {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": f"Sentry Event: {resource} {action}"},
                "template": "blue",
            },
            "elements": [
                {
                    "tag": "div",
                    "text": {
                        "tag": "lark_md",
                        "content": f"```json\n{json.dumps(data, indent=2, ensure_ascii=False)[:2000]}\n```",
                    },
                }
            ],
        },
    }


def send_to_feishu(card):
    resp = requests.post(FEISHU_WEBHOOK_URL, json=card, timeout=10)
    return resp.status_code, resp.text


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "sentry-feishu-webhook"})


@app.route("/webhook/sentry", methods=["POST"])
def sentry_webhook():
    signature = request.headers.get("Sentry-Hook-Signature", "")
    if SENTRY_CLIENT_SECRET and not verify_sentry_signature(request.data, signature):
        return jsonify({"error": "invalid signature"}), 401

    resource = request.headers.get("Sentry-Hook-Resource", "")
    action = request.headers.get("Sentry-Hook-Action", "")

    if resource == "issue" and action != "created":
        return jsonify({"msg": f"ignored: issue {action}"}), 200

    data = request.json
    if not data:
        return jsonify({"error": "empty body"}), 400

    card = build_feishu_card(data, resource, action)
    status_code, resp_text = send_to_feishu(card)

    return jsonify({
        "msg": "forwarded to feishu",
        "feishu_status": status_code,
        "feishu_response": resp_text,
    }), 200
