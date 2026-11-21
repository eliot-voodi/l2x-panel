#!/usr/bin/env python3
from io import StringIO
from pathlib import Path
import paramiko

pkey = paramiko.RSAKey.from_private_key(
    StringIO((Path.home() / ".ssh" / "id_rsa_brathe").read_text()),
    password="Jxr0fldblf228!@",
)


def run(host, cmd, timeout=60):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username="root", pkey=pkey, timeout=20, allow_agent=False, look_for_keys=False)
    _, o, e = c.exec_command(cmd, timeout=timeout)
    out = o.read().decode("utf-8", "replace")
    err = e.read().decode("utf-8", "replace")
    c.close()
    return out + (("\nERR:" + err[:2000]) if err.strip() else "")


print(
    run(
        "web.ro0t.dev",
        r"""
python3 - <<'PY'
import json
st=json.load(open("/var/lib/l2xpanel/store.json"))
g=next(x for x in st["groups"] if x["id"]=="g_1apBj3F9dwB")
print("group", {k:g.get(k) for k in ("id","name","inbounds","ib_mode","allowed_tags","outbound")})
c=next(x for x in st["clients"] if x["email"]=="ilable")
print("client ib", c.get("inbounds"), "ib_mode", c.get("ib_mode"), "group", c.get("group_id"))
for core in st.get("cores") or []:
  if core.get("id")=="core_Hg7tdanKgLe":
    print("core ibs", [(i.get("tag"),i.get("id")) for i in core.get("inbounds") or []])
PY
""",
    )
)
