#!/usr/bin/env python3
"""OpenAI 호환 가짜 서버(데모·종단 검증용). 받은 인벤토리 집계를 읽어 간단한 리포트를 돌려준다.

    python3 scripts/fake_openai.py --port 8199      # 서버 설정: base_url http://127.0.0.1:8199/v1, trust_zone internal
요청의 Authorization 헤더 유무와 모델명은 stdout 에 기록한다(키 값 자체는 기록하지 않는다).
"""
from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def write_report(user_prompt: str) -> str:
    m = re.search(r"<inventory_facts>\n(.*)\n</inventory_facts>", user_prompt, re.S)
    facts = json.loads(m.group(1)) if m else {}
    totals, pol = facts.get("totals", {}), facts.get("kernel_policy", {})
    lines = ["## 1. 요약", f"전체 {totals.get('hosts', '?')}대 중 하한선 미달 {pol.get('noncompliant_count', '?')}대, "
             f"재부팅 필요 {totals.get('reboot_required', '?')}대입니다.", "", "## 7. 권고 조치"]
    lines += [f"- `{h['hostname']}` 커널을 {h['min_kernel']} 이상으로 올린다" for h in facts.get("noncompliant_hosts", [])[:5]]
    return "\n".join(lines)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        auth = self.headers.get("Authorization")
        print(f"POST {self.path} model={body.get('model')} auth={'Bearer ***' if auth else 'none'} "
              f"key_ok={auth == 'Bearer ' + (self.server.expect_key or '') if self.server.expect_key else 'n/a'}", flush=True)
        text = write_report(body["messages"][1]["content"]) if len(body.get("messages", [])) > 1 else "OK"
        out = json.dumps({"choices": [{"message": {"content": text}}], "model": body.get("model"),
                          "usage": {"prompt_tokens": 100, "completion_tokens": 50}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8199)
    ap.add_argument("--expect-key", default="", help="이 키가 Bearer 로 오는지 로그에 true/false 로 남긴다")
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.expect_key = a.expect_key
    print(f"fake openai on {a.host}:{a.port}", flush=True)
    srv.serve_forever()
