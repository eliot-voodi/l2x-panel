#!/usr/bin/env python3
"""Deploy client-inbound fix to master+buh, normalize tags, sync, probe."""
from io import StringIO
from pathlib import Path
import json
import time
import paramiko

ROOT = Path(__file__).resolve().parents[2]
pkey = paramiko.RSAKey.from_private_key(
    StringIO((Path.home() / ".ssh" / "id_rsa_brathe").read_text()),
    password="Jxr0fldblf228!@",
)
FILES = ["xray_runtime.py", "nodes.py", "app.py", "VERSION"]


def ssh(host):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username="root", pkey=pkey, timeout=20, allow_agent=False, look_for_keys=False)
    return c


def run(c, cmd, timeout=180):
    _, o, e = c.exec_command(cmd, timeout=timeout)
    out = o.read().decode("utf-8", "replace")
    err = e.read().decode("utf-8", "replace")
    return out + (("\nERR:" + err[:3000]) if err.strip() else "")


def put_files(host, dirs):
    c = ssh(host)
    sftp = c.open_sftp()
    for d in dirs:
        for name in FILES:
            local = ROOT / "panel" / name
            if name == "VERSION":
                local = ROOT / "VERSION"
                if not local.exists():
                    local = ROOT / "panel" / "VERSION"
            remote = f"{d}/{name}"
            sftp.put(str(local), remote)
            print(f"PUT {host} {remote}")
    sftp.close()
    c.close()


put_files("web.ro0t.dev", ["/opt/l2xpanel"])
put_files("buh.ro0t.dev", ["/opt/l2xpanel", "/opt/l2xpanel-live", "/opt/l2xpanel-next"])

c = ssh("web.ro0t.dev")
print("=== normalize + restart master + sync buh ===")
print(
    run(
        c,
        r"""
systemctl restart l2xpanel
sleep 2
systemctl is-active l2xpanel
cd /opt/l2xpanel
PYTHONPATH=/opt/l2xpanel .venv/bin/python - <<'PY'
import json, sys, os
sys.path.insert(0,'/opt/l2xpanel')
import xray_runtime as xray
import nodes as nodes_mod
import cores as cores_mod

path='/var/lib/l2xpanel/store.json'
st=json.load(open(path))
# Normalize client/group inbound tags to canonical casing
known={str(i['tag']).lower(): str(i['tag']) for i in xray.client_capable_inbounds(st) if i.get('tag')}
changed=False
for c in st.get('clients') or []:
    ibs=c.get('inbounds')
    if not isinstance(ibs, list):
        continue
    new=[]
    for t in ibs:
        k=str(t or '').strip().lower()
        if k in known and known[k] not in new:
            new.append(known[k])
    if new != ibs:
        c['inbounds']=new
        # personal list with ib_mode all is unused when group set — clear noise
        if c.get('group_id') and c.get('ib_mode')=='all':
            c['inbounds']=[]
        changed=True
        print('fixed client', c.get('email'), '->', c.get('inbounds'))
for g in st.get('groups') or []:
    ibs=g.get('inbounds')
    if not isinstance(ibs, list):
        continue
    new=[]
    for t in ibs:
        k=str(t or '').strip().lower()
        if k in known and known[k] not in new:
            new.append(known[k])
    if new != ibs:
        g['inbounds']=new
        changed=True
        print('fixed group', g.get('name'), '->', new)
if changed:
    json.dump(st, open(path,'w'), ensure_ascii=False, indent=2)
    print('store saved')
else:
    print('no tag changes')

# Rebuild + push buh
st=json.load(open(path))
node=next(n for n in nodes_mod.ensure_list(st) if 'buh' in str(n.get('domain') or '').lower())
print('push', node.get('name'), node.get('domain'))
payload=nodes_mod.build_payload(st, node, xray.build_config)
print('payload groups', len(payload.get('groups') or []), 'clients', len(payload.get('clients') or []))
# Simulate agent build
fake={'clients': payload['clients'], 'groups': payload.get('groups') or [], 'inbounds': payload['inbounds'],
      'outbounds_custom': payload.get('outbounds_custom') or [], 'routes': payload.get('routes') or [],
      'balancers': payload.get('balancers') or {}, 'dns': payload.get('dns') or {},
      'xray_settings': payload.get('xray_settings') or {}, 'settings': {}}
cfg=xray.build_config(fake)
for i in cfg.get('inbounds') or []:
    if i.get('tag')=='Buharest':
        cls=(i.get('settings') or {}).get('clients') or []
        print('SIM Buharest clients', len(cls), [x.get('email') for x in cls[:10]])
r=nodes_mod.push(node, payload, master_host='web.ro0t.dev', timeout=120)
print('push result', {k:r.get(k) for k in ('ok','error','warnings') if k in r or True})
PY
""",
        timeout=180,
    )
)
c.close()

time.sleep(2)
c = ssh("buh.ro0t.dev")
print("=== buh verify + probe ===")
print(
    run(
        c,
        r"""
python3 - <<'PY'
import json, subprocess, time
from pathlib import Path
d=json.load(open('/etc/xray/config.json'))
UID=None; PBK=None; SID=None
for i in d.get('inbounds') or []:
  if i.get('tag')!='Buharest':
    continue
  cls=(i.get('settings') or {}).get('clients') or []
  print('Buharest clients', len(cls), [(c.get('email'), c.get('id')) for c in cls[:15]])
  r=(i.get('streamSettings') or {}).get('realitySettings') or {}
  print('shortIds', r.get('shortIds'))
  # get public key via xray x25519
  priv=r.get('privateKey') or ''
  SID=(r.get('shortIds') or ['da'])[0]
  import subprocess as sp
  # Try openssl-less: use xray
  p=sp.run(['/usr/local/bin/xray','x25519','-i',priv], capture_output=True, text=True)
  print('x25519 out', (p.stdout or p.stderr)[:200])
  for line in (p.stdout or '').splitlines():
    if 'Password' in line or 'public' in line.lower() or line.strip().startswith('Public'):
      PBK=line.split(':')[-1].strip() or line.split()[-1]
  # fallback parse "Private key:" / "Public key:"
  for line in (p.stdout or '').splitlines():
    low=line.lower()
    if 'public' in low and ':' in line:
      PBK=line.split(':',1)[1].strip()
  for c in cls:
    if c.get('email')=='ilable' or str(c.get('email') or '').startswith('ilable'):
      UID=c.get('id'); break
  if not UID and cls:
    UID=cls[0].get('id')
print('probe uid', UID, 'pbk', PBK, 'sid', SID)
if not UID or not PBK:
  raise SystemExit('missing uid/pbk')
cfg={
 "log":{"loglevel":"warning"},
 "inbounds":[{"tag":"socks","listen":"127.0.0.1","port":19741,"protocol":"socks","settings":{"udp":True}}],
 "outbounds":[{
   "tag":"proxy","protocol":"vless",
   "settings":{"vnext":[{"address":"buh.ro0t.dev","port":443,"users":[{"id":UID,"encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"raw","security":"reality",
     "realitySettings":{"serverName":"vk.ru","fingerprint":"firefox","publicKey":PBK,"shortId":SID,"spiderX":"/"}}
 },{"tag":"direct","protocol":"freedom"}],
 "routing":{"rules":[{"type":"field","outboundTag":"proxy","network":"tcp,udp"}]}
}
Path('/tmp/p19741.json').write_text(json.dumps(cfg))
log=open('/tmp/p19741.log','w')
p=subprocess.Popen(['/usr/local/bin/xray','run','-config','/tmp/p19741.json'],stdout=log,stderr=log)
time.sleep(1)
r=subprocess.run(['curl','-sS','--max-time','12','-o','/dev/null','-w','%{http_code}','--socks5-hostname','127.0.0.1:19741','https://www.gstatic.com/generate_204'],capture_output=True,text=True)
print('probe', r.stdout, (r.stderr or '')[:200], 'rc', r.returncode)
print('xraylog', Path('/tmp/p19741.log').read_text()[-500:])
p.terminate(); p.wait(timeout=3)
PY
""",
        timeout=90,
    )
)
c.close()
