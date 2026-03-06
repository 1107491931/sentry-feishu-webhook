from flask import Flask, request, jsonify
import requests
import os
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

FEISHU_WEBHOOK_URL = os.environ.get("FEISHU_WEBHOOK_URL", "")
SENTRY_API_TOKEN = os.environ.get("SENTRY_API_TOKEN", "")
SENTRY_BASE_URL = os.environ.get("SENTRY_BASE_URL", "https://sentry-us.addx.live")
SENTRY_ORG = os.environ.get("SENTRY_ORG", "sentry")
SENTRY_PROJECT = os.environ.get("SENTRY_PROJECT", "vh-ios")
CRON_SECRET = os.environ.get("CRON_SECRET", "")
CHECK_HOURS = int(os.environ.get("CHECK_HOURS", "1"))


def sentry_headers():
    return {"Authorization": f"Bearer {SENTRY_API_TOKEN}"}


def get_latest_releases(limit=2):
    url = f"{SENTRY_BASE_URL}/api/0/projects/{SENTRY_ORG}/{SENTRY_PROJECT}/releases/"
    resp = requests.get(url, headers=sentry_headers(), params={"per_page": limit}, timeout=8)
    resp.raise_for_status()
    return resp.json()


def get_new_issues_for_release(release_version, since_hours=1):
    url = f"{SENTRY_BASE_URL}/api/0/projects/{SENTRY_ORG}/{SENTRY_PROJECT}/issues/"
    since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).strftime("%Y-%m-%dT%H:%M:%S")
    params = {
        "query": f"firstRelease:{release_version} firstSeen:>{since}",
        "sort": "date",
        "per_page": 25,
    }
    resp = requests.get(url, headers=sentry_headers(), params=params, timeout=8)
    resp.raise_for_status()
    return resp.json()


def build_issues_card(issues, release_version, project):
    issue_lines = []
    for i, issue in enumerate(issues[:10], 1):
        title = issue.get("title", "Unknown")
        level = issue.get("level", "error")
        url = issue.get("permalink", "")
        culprit = issue.get("culprit", "")
        line = f"{i}. **[{level.upper()}]** [{title}]({url})"
        if culprit:
            line += f"\n    `{culprit}`"
        issue_lines.append(line)

    remaining = len(issues) - 10
    if remaining > 0:
        issue_lines.append(f"\n... and {remaining} more issues")

    return {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": f"Sentry: {len(issues)} New Issues Found"},
                "template": "red",
            },
            "elements": [
                {
                    "tag": "div",
                    "fields": [
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"**Project:**\n{project}"}},
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"**Release:**\n{release_version}"}},
                    ],
                },
                {"tag": "hr"},
                {"tag": "div", "text": {"tag": "lark_md", "content": "\n".join(issue_lines)}},
            ],
        },
    }


def send_to_feishu(card):
    resp = requests.post(FEISHU_WEBHOOK_URL, json=card, timeout=10)
    return resp.status_code, resp.text


@app.route("/api/cron/check", methods=["GET"])
def cron_check():
    secret = request.args.get("secret", "")
    if CRON_SECRET and secret != CRON_SECRET:
        return jsonify({"error": "unauthorized"}), 401

    if not SENTRY_API_TOKEN:
        return jsonify({"error": "SENTRY_API_TOKEN not configured"}), 500

    if not FEISHU_WEBHOOK_URL:
        return jsonify({"error": "FEISHU_WEBHOOK_URL not configured"}), 500

    releases = get_latest_releases(2)
    if not releases:
        return jsonify({"msg": "no releases found"}), 200

    latest_release = releases[0]["version"]

    new_issues = get_new_issues_for_release(latest_release, since_hours=CHECK_HOURS)

    if not new_issues:
        return jsonify({
            "msg": "no new issues",
            "release": latest_release,
            "checked_hours": CHECK_HOURS,
        }), 200

    card = build_issues_card(new_issues, latest_release, SENTRY_PROJECT)
    status_code, resp_text = send_to_feishu(card)

    return jsonify({
        "msg": f"found {len(new_issues)} new issues",
        "release": latest_release,
        "feishu_status": status_code,
        "feishu_response": resp_text,
    }), 200
