#!/usr/bin/env bash
# Full Auto: IKEv2/IPsec + Web Panel (FastAPI) for managing EAP-MSCHAPv2 users
# OS: Ubuntu/Debian
# Run as root:  bash ikev2_panel_install.sh
set -euo pipefail

# ======== CONFIG (change if you like) ========
VPN_USER_DEFAULT="${VPN_USER_DEFAULT:-admin}"
VPN_PASS_DEFAULT="${VPN_PASS_DEFAULT:-123456}"

PANEL_USER="${PANEL_USER:-paneladmin}"
PANEL_PASS="${PANEL_PASS:-panel123}"
PANEL_PORT="${PANEL_PORT:-8080}"

VPN_NET="${VPN_NET:-10.10.10.0/24}"
VPN_DNS1="${VPN_DNS1:-1.1.1.1}"
VPN_DNS2="${VPN_DNS2:-8.8.8.8}"
COUNTRY="${COUNTRY:-SA}"
ORG="${ORG:-IKEv2 VPN}"
STATE="${STATE:-Riyadh}"
CITY="${CITY:-Riyadh}"

APP_DIR="/opt/ikev2-panel"
ENV_FILE="/etc/ikev2-panel.env"
SYSTEMD_UNIT="ikev2-panel.service"
SECRETS_FILE="/etc/ipsec.secrets"
IPSEC_DIR="/etc/ipsec.d"
PRIMARY_IF="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')"
# ============================================

if [[ $EUID -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi

echo "[1/8] Installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ufw iptables python3 python3-venv python3-pip

# Detect whether strongSwan is installed
if ! dpkg -s strongswan >/dev/null 2>&1; then
  echo "[2/8] strongSwan not found. Installing and configuring IKEv2..."
  apt-get install -y strongswan strongswan-pki charon-systemd \
    libcharon-extra-plugins libstrongswan-extra-plugins

  # Enable IP forwarding
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null || true
  sed -i 's/^#\?net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf

  mkdir -p "$IPSEC_DIR"/{private,certs,cacerts}

  # Public IP / Server ID
  PUB_IP="$(curl -s4 https://ifconfig.me || true)"
  if [[ -z "${PUB_IP}" ]]; then
    PUB_IP="$(ip -4 addr show dev "$PRIMARY_IF" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  fi
  SERVER_ID="${SERVER_ID:-$PUB_IP}"

  echo "[3/8] Generating CA and server certificates..."
  rm -f "$IPSEC_DIR"/private/ikev2*.key "$IPSEC_DIR"/certs/ikev2*.crt "$IPSEC_DIR"/cacerts/ikev2*.crt || true

  ipsec pki --gen --type rsa --size 4096 --outform pem > "$IPSEC_DIR/private/ikev2-ca.key.pem"
  ipsec pki --self --ca --lifetime 3650 \
    --in "$IPSEC_DIR/private/ikev2-ca.key.pem" --type rsa \
    --dn "C=${COUNTRY}, O=${ORG}, CN=${ORG} CA" \
    --outform pem > "$IPSEC_DIR/cacerts/ikev2-ca.crt.pem"

  ipsec pki --gen --type rsa --size 4096 --outform pem > "$IPSEC_DIR/private/ikev2-server.key.pem"
  ipsec pki --pub --in "$IPSEC_DIR/private/ikev2-server.key.pem" --type rsa \
  | ipsec pki --issue --lifetime 1825 --cacert "$IPSEC_DIR/cacerts/ikev2-ca.crt.pem" \
      --cakey "$IPSEC_DIR/private/ikev2-ca.key.pem" \
      --dn "C=${COUNTRY}, O=${ORG}, CN=${SERVER_ID}" \
      --san "${SERVER_ID}" \
      --flag serverAuth --flag ikeIntermediate \
      --outform pem > "$IPSEC_DIR/certs/ikev2-server.crt.pem"

  chmod 600 "$IPSEC_DIR/private/"*.pem

  cat >/etc/ipsec.conf <<EOF
config setup
  uniqueids=never
  charondebug="ike 1, knl 1, cfg 0, chd 0, net 0, enc 0, lib 0"

conn ikev2-eap
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes
  dpdaction=clear
  dpddelay=300s
  rekey=no
  left=%any
  leftid=${SERVER_ID}
  leftsubnet=0.0.0.0/0
  leftcert=ikev2-server.crt.pem
  leftsendcert=always
  right=%any
  rightsourceip=${VPN_NET}
  rightdns=${VPN_DNS1},${VPN_DNS2}
  rightsendcert=never
  eap_identity=%identity
  ike=aes256-sha256-modp2048,aes256-sha1-modp2048!
  esp=aes256-sha256,aes256-sha1!
  authby=pubkey
  eap_mschapv2=yes
EOF

  if ! [[ -f "$SECRETS_FILE" ]]; then
    cat >"$SECRETS_FILE" <<EOF
: RSA ikev2-server.key.pem
${VPN_USER_DEFAULT} : EAP "${VPN_PASS_DEFAULT}"
EOF
  else
    if ! grep -q ": RSA ikev2-server.key.pem" "$SECRETS_FILE"; then
      sed -i '1i : RSA ikev2-server.key.pem' "$SECRETS_FILE"
    fi
    if ! grep -q "^${VPN_USER_DEFAULT}\s*:" "$SECRETS_FILE"; then
      echo "${VPN_USER_DEFAULT} : EAP \"${VPN_PASS_DEFAULT}\"" >> "$SECRETS_FILE"
    fi
  fi
  chmod 600 "$SECRETS_FILE"

  echo "[4/8] Firewall + NAT..."
  ufw allow OpenSSH
  ufw allow 500/udp
  ufw allow 4500/udp
  ufw --force enable

  UFW_BEFORE_RULES="/etc/ufw/before.rules"
  if ! grep -q "IKEv2 NAT" "$UFW_BEFORE_RULES"; then
    sed -i '1i # IKEv2 NAT' "$UFW_BEFORE_RULES"
    cat >>"$UFW_BEFORE_RULES" <<EOF

# IKEv2 NAT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s ${VPN_NET} -o ${PRIMARY_IF} -j MASQUERADE
COMMIT
EOF
  fi
  ufw reload

  systemctl enable strongswan-starter
  systemctl restart strongswan-starter

  cp "$IPSEC_DIR/cacerts/ikev2-ca.crt.pem" /root/IKEv2_CA.crt.pem || true
else
  echo "[2/8] strongSwan found. Skipping VPN base setup."
fi

echo "[5/8] Creating panel app..."
mkdir -p "$APP_DIR"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip wheel
"$APP_DIR/venv/bin/pip" install fastapi uvicorn jinja2 python-multipart

# App code
cat >"$APP_DIR/app.py" <<'PYAPP'
import os, re, secrets, fcntl
from pathlib import Path
from typing import List
from fastapi import FastAPI, Request, Form, Depends, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
import subprocess
import html

SECRETS_FILE = Path("/etc/ipsec.secrets")
LOCK_FILE = Path("/var/lock/ikev2_panel.lock")
security = HTTPBasic()

PANEL_USER = os.getenv("PANEL_USER", "paneladmin")
PANEL_PASS = os.getenv("PANEL_PASS", "panel123")

app = FastAPI(title="IKEv2 User Panel")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

def auth(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, PANEL_USER)
    correct_pass = secrets.compare_digest(credentials.password, PANEL_PASS)
    if not (correct_user and correct_pass):
        resp = Response(status_code=status.HTTP_401_UNAUTHORIZED)
        resp.headers["WWW-Authenticate"] = 'Basic realm="IKEv2 Panel"'
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="IKEv2 Panel"'})
    return True

def read_users() -> List[str]:
    if not SECRETS_FILE.exists():
        return []
    users = []
    with open(SECRETS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#"): continue
            # match lines like: username : EAP "password"
            m = re.match(r'^([^:\s]+)\s*:\s*EAP\s+"', line)
            if m:
                users.append(m.group(1))
    return users

def modify_users(new_lines: List[str]):
    # Lock to avoid concurrent writes
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK_FILE, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data=[]
        if SECRETS_FILE.exists():
            with open(SECRETS_FILE, "r", encoding="utf-8") as f:
                data = f.readlines()
        # keep RSA key line(s), remove all EAP lines
        kept=[]
        for ln in data:
            if ': RSA ' in ln:
                kept.append(ln)
        kept += [l if l.endswith("\n") else l+"\n" for l in new_lines]
        with open(SECRETS_FILE, "w", encoding="utf-8") as f:
            f.writelines(kept)
        fcntl.flock(lock, fcntl.LOCK_UN)

    # reload strongSwan
    try:
        subprocess.run(["systemctl","reload","strongswan-starter"], check=False)
    except Exception:
        pass

def sanitize_user(u: str) -> str:
    # allow alnum, underscore, dash, dot
    if not re.match(r'^[A-Za-z0-9_.-]{1,64}$', u):
        raise ValueError("Invalid username")
    return u

def build_eap_line(u: str, p: str) -> str:
    # escape quotes in password
    p = p.replace('"', '\\"')
    return f'{u} : EAP "{p}"'

@app.get("/", response_class=HTMLResponse)
def home(request: Request, _=Depends(auth)):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "users": read_users()
    })

@app.post("/add", response_class=RedirectResponse)
def add_user(username: str = Form(...), password: str = Form(...), _=Depends(auth)):
    try:
        u = sanitize_user(username.strip())
        if len(password) < 4:
            raise ValueError("Password too short")
        users = read_users()
        new_lines=[]
        # remove old entry of same user
        for user in users:
            if user != u:
                new_lines.append(build_eap_line(user, "KEEP_PLACEHOLDER"))
        # We need original passwords for others; read raw lines instead:
        # Rebuild from file lines to keep other users' passwords
        preserved=[]
        if SECRETS_FILE.exists():
            with open(SECRETS_FILE,"r",encoding="utf-8") as f:
                for ln in f:
                    if ': EAP ' in ln:
                        m = re.match(r'^([^:\s]+)\s*:\s*EAP\s+"(.*)"\s*$', ln.strip())
                        if m and m.group(1)!=u:
                            preserved.append(ln.strip())
        preserved.append(build_eap_line(u, password))
        modify_users(preserved)
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/?error={html.escape(str(e))}", status_code=303)

@app.post("/delete", response_class=RedirectResponse)
def delete_user(username: str = Form(...), _=Depends(auth)):
    try:
        u = sanitize_user(username.strip())
        preserved=[]
        if SECRETS_FILE.exists():
            with open(SECRETS_FILE,"r",encoding="utf-8") as f:
                for ln in f:
                    if ': EAP ' in ln:
                        m = re.match(r'^([^:\s]+)\s*:\s*EAP\s+"(.*)"\s*$', ln.strip())
                        if m and m.group(1)!=u:
                            preserved.append(ln.strip())
        modify_users(preserved)
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/?error={html.escape(str(e))}", status_code=303)

@app.get("/api/users", response_class=PlainTextResponse)
def api_users(_=Depends(auth)):
    return "\n".join(read_users())

PYAPP

# Templates
mkdir -p "$APP_DIR/templates"
cat >"$APP_DIR/templates/index.html"<<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>IKEv2 User Panel</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:0;padding:24px;background:#0b1020;color:#e8eefc}
    .card{max-width:760px;margin:0 auto;background:#141b34;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.25);padding:20px}
    h1{margin:0 0 16px;font-size:22px}
    .row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
    input,button,select{padding:10px 12px;border-radius:10px;border:1px solid #2a335a;background:#0f1630;color:#e8eefc}
    button{cursor:pointer;border:0;background:#2f80ed}
    table{width:100%;border-collapse:collapse;margin-top:12px}
    th,td{padding:10px;border-bottom:1px solid #2a335a}
    .muted{opacity:.8;font-size:13px}
    .danger{background:#e74c3c}
    .ok{color:#67e480}
  </style>
</head>
<body>
  <div class="card">
    <h1>IKEv2 User Panel</h1>
    <div class="muted">HTTP Basic protected. After changes, strongSwan reloads automatically.</div>

    <form method="post" action="/add">
      <div class="row">
        <input name="username" placeholder="username" required>
        <input name="password" placeholder="password" required>
        <button type="submit">Add / Update</button>
      </div>
    </form>

    <h3>Users</h3>
    <table>
      <thead><tr><th>User</th><th style="width:140px">Action</th></tr></thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td>{{u}}</td>
          <td>
            <form method="post" action="/delete" onsubmit="return confirm('Delete {{u}}?')">
              <input type="hidden" name="username" value="{{u}}">
              <button class="danger" type="submit">Delete</button>
            </form>
          </td>
        </tr>
        {% endfor %}
        {% if users|length == 0 %}
        <tr><td colspan="2" class="muted">No users yet.</td></tr>
        {% endif %}
      </tbody>
    </table>

    <p class="muted">API: <code>GET /api/users</code></p>
  </div>
</body>
</html>
HTML

echo "[6/8] Writing env and systemd..."
cat >"$ENV_FILE" <<EOF
PANEL_USER=${PANEL_USER}
PANEL_PASS=${PANEL_PASS}
EOF
chmod 600 "$ENV_FILE"

cat >"/etc/systemd/system/${SYSTEMD_UNIT}" <<EOF
[Unit]
Description=IKEv2 User Panel (FastAPI)
After=network-online.target
Wants=network-online.target

[Service]
User=root
Group=root
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/uvicorn app:app --host 0.0.0.0 --port ${PANEL_PORT}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo "[7/8] Opening firewall for panel port ${PANEL_PORT}..."
ufw allow ${PANEL_PORT}/tcp || true
systemctl daemon-reload
systemctl enable "${SYSTEMD_UNIT}"
systemctl restart "${SYSTEMD_UNIT}"

echo "[8/8] Final checks..."
sleep 1
systemctl --no-pager --full status "${SYSTEMD_UNIT}" || true

# Info
SERVER_IP="$(curl -s4 https://ifconfig.me || true)"
if [[ -z "$SERVER_IP" ]]; then
  SERVER_IP="$(ip -4 addr show dev "$PRIMARY_IF" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
fi

echo
echo "==============================================================="
echo " IKEv2/IPsec + Web Panel installed."
echo
echo " Panel URL     : http://${SERVER_IP}:${PANEL_PORT}"
echo " Panel Auth    : ${PANEL_USER} / ${PANEL_PASS}"
echo " Secrets file  : ${SECRETS_FILE}"
echo " Panel service : systemctl status ${SYSTEMD_UNIT}"
echo
echo " VPN users now :"
awk '/: EAP /{print $1}' ${SECRETS_FILE} || true
echo
echo " Note: Import /root/IKEv2_CA.crt.pem on phones if you set up the VPN now."
echo " To change panel credentials:"
echo "   sed -i 's/^PANEL_USER=.*/PANEL_USER=newuser/' ${ENV_FILE}"
echo "   sed -i 's/^PANEL_PASS=.*/PANEL_PASS=newpass/' ${ENV_FILE}"
echo "   systemctl restart ${SYSTEMD_UNIT}"
echo "==============================================================="
