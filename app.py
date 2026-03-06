from flask import Flask, request, jsonify
import requests
import json
import os
import hmac
import hashlib

app = Flask(__name__)

FEISHU_WEBHOOK_URL = os.environ.get(
    "FEISHU_WEBHOOK_URL",
    "https://open.feishu.cn/open-apis/bot/v2/hook/d5098cfa-d2e7-4344-9fac-263dfa81dcab",
)
SENTRY_CLIENT_SECRET = os.environ.get("SENTRY_CLIENT_SECRET", "")


def verify_sentry_signature(payload, signature):
    """Verify Sentry webhook signature if secret is configured."""
    if not SENTRY_CLIENT_SECRET:
        return True
    expected = hmac.new(
        SENTRY_CLIENT_SECRET.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def build_feishu_card(data, resource, action):
    """Build Feishu interactive card message from Sentry webhook data."""

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

        card = {
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
        return card

    # Fallback for other event types
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
    """Send message to Feishu webhook."""
    resp = requests.post(FEISHU_WEBHOOK_URL, json=card, timeout=10)
    return resp.status_code, resp.text


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "sentry-feishu-webhook"})


@app.route("/webhook/sentry", methods=["POST"])
def sentry_webhook():
    """Receive Sentry webhook and forward to Feishu."""

    # Verify signature
    signature = request.headers.get("Sentry-Hook-Signature", "")
    if SENTRY_CLIENT_SECRET and not verify_sentry_signature(request.data, signature):
        return jsonify({"error": "invalid signature"}), 401

    resource = request.headers.get("Sentry-Hook-Resource", "")
    action = request.headers.get("Sentry-Hook-Action", "")

    # Only forward new issues (ignore existing issues from old versions)
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
