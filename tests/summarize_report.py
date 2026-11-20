#!/usr/bin/env python3
"""Resume um relatório `ohboyscan audit --json` em uma linha."""
import json
import sys

d = json.load(open(sys.argv[1]))
parts = []
for f in d["findings"]:
    s = f'{f["category"]}: {f.get("path", "")}'
    if f.get("before") or f.get("after"):
        s += f' [{f.get("before", "")} -> {f.get("after", "")}]'
    parts.append(s)
api = "API não consultada" if d["checked"]["items"] == 0 else f'{d["checked"]["items"]} itens/{d["checked"]["scripts"]} scripts'
print(f'{api}; ' + ("; ".join(parts) if parts else "sem achados"))
