import json
import os
import time

LOG_PATH = "/app/logs/connections.jsonl"


def create_logger():
    os.makedirs("/app/logs", exist_ok=True)

    def log(event):
        event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    return log
