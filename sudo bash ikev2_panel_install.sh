#!/usr/bin/env bash
# IKEv2/IPsec + Web Panel + Apache CA download (Ubuntu/Debian)
# Fixed edition: correct BasicAuth compare, robust cert SAN, safe secrets edits.
set -euo pipefail

# -------- CONFIG (override via env) --------
PANEL_USER="${PANEL_USER:-paneladmin}"
PANEL_PASS="${PANEL_PASS:-panel123}"
PANEL_PORT="${PANEL_PORT:-8080}"

VPN_USER_DEFAULT="${VPN_USER_DEFAULT:-admin}"
VPN_PASS_DEFAULT="${VPN_PASS_DEFAULT:-123456}"

VPN_NET="${VPN_NET:-10.10.10.0/24}"
VPN_DNS1="${VPN_DNS1:-1.1.1.1}"
VPN_DNS2="${VPN_DNS2:-8.8.8.8}"

COUNTRY="${COUNTRY:-SA}"
ORG="${ORG:-IKEv2 VPN}"
STATE="${STATE:-Riyadh}"
CITY="${CITY:-Riyadh}"
# ------------------------------------------

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }

APP_DIR="/opt/ikev2-panel"
ENV_FILE="/etc/ikev2-panel.env"
SYSTEMD_UNIT="ikev2-panel.service"
SECRETS_FILE="/etc/ipsec.secrets"
IPSEC_DIR="/etc/ipsec.d"
UFW_BEFORE_RULES="/etc/ufw/before.rules"

PRIMARY_IF="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}' || true)"
SERVER_IP="$(curl -s4 https://ifconfig.me || true)"
if [[ -z "$SERVER_IP" && -n "$PRIMARY_IF" ]]; then
  SERVER_IP="$(ip -4 addr show dev "$PRIMARY_IF" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
fi
SERVER_ID="${SERVER_ID:-$SERVER_IP}"  # can be DNS or IP

echo "[1/10] Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ufw iptables python3 python3-venv python3-pip apache2 \
                   strongswan strongswan-pki charon-systemd \
                   libcharon-extra-plugins libstrongswan-extra-plugins openssl

echo "[2/10] Enable IP forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sed -i 's/^#\?net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf || true

echo "[3/10] PKI & strongSwan base"
mkdir -p "$IPSEC_DIR"/{private,certs,cacerts}

# If no CA exists, create new CA
if [[ ! -s "$IPSEC_DIR/cacerts/ikev2-ca.crt.pem" || ! -s "$IPSEC_DIR/private/ikev2-ca.key.pem" ]]; then
  ipsec pki --gen --type rsa --size 4096 --outform pem > "$IPSEC_DIR/private/ikev2-ca.key.pem"
  ipsec pki --self --ca --lifetime 3650 \
    --in "$IPSEC_DIR/private/ikev2-ca.key.pem" --type rsa \
    --dn "C=${COUNTRY}, ST=${STATE}, L=${CITY}, O=${ORG}, CN=${ORG} CA" \
    --outform pem > "$IPSEC_DIR/cacerts/ikev2-ca.crt.pem"
fi

# Always (re)issue server cert for the chosen SERVER_ID
rm -f "$IPSEC_DIR/private/ikev2-server.key.pem" "$IPSEC_DIR/certs/ikev2-server.crt.pem"
ipsec pki --gen --type rsa --size 4096 --outform pem > "$IPSEC_DIR/private/ikev2-server.key.pem"
ipsec pki --pub --in "$IPSEC_DIR/private/ikev2-server.key.pem" --type rsa \
| ipsec pki --issue --lifetime 1825 --cacert "$IPSEC_DIR/cacerts/ikev2-ca.crt.pem" \
    --cakey "$IPSEC_DIR/private/ikev2-ca.key.pem" \
    --dn "C=${COUNTRY}, ST=${STATE}, L=${CITY}, O=${ORG}, CN=${SERVER_ID}" \
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
  authby=pubkey
  eap_mschapv2=yes
  eap_identity=%identity
  ike=aes256-sha256-modp2048,aes256-sha1-modp2048!
  esp=aes256-sha256,aes256-sha1!
EOF

# Initialize secrets file safely
if [[ -f "$SECRETS_FILE" ]]; then
  cp -a "$SECRETS_FILE" "${SECRETS_FILE}.bak.$(date +%s)"
fi
touch "$SECRETS_FILE"
chmod 600 "$SECRETS_FILE"
# Ensure RSA line exists
grep -q ": RSA ikev2-server.key.pem" "$SECRETS_FILE" || sed -i '1i : RSA ikev2-server.key.pem' "$SECRETS_FILE"
# Ensure default user exists
grep -q "^${VPN_USER_DEFAULT}\s*:\s*EAP" "$SECRETS_FILE" || echo "${VPN_USER_DEFAULT} : EAP \"${VPN_PASS_DEFAULT}\"" >> "$SECRETS_FILE"

echo "[4/10] Firewall + NAT"
ufw allow OpenSSH || true
ufw allow 500/udp || true
ufw allow 4500/udp || true
ufw allow 80/tcp || true
ufw allow ${PANEL_PORT}/tcp || true
ufw --force enable

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
ufw reload || true

systemctl enable strongswan-starter
systemctl restart strongswan-starter

# Export CA for clients and serve via Apache
cp "$IPSEC_DIR/cacerts/ikev2-ca.crt.pem" /root/IKEv2_CA.crt.pem
cp /root/IKEv2_CA.crt.pem /var/www/html/IKEv2_CA.crt.pem
chmod 644 /var/www/html/IKEv2_CA.crt.pem
systemctl enable apache2
systemctl restart apache2

echo "[5/10] Panel: venv & deps"
mkdir -p "$APP_DIR"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip wheel
"$APP_DIR/venv/bin/pip" install fastapi uvicorn jinja2 python-multipart

echo "[6/10] Panel app code"
cat >"$APP_DIR/app.py" <<'PYAPP'
import os, re, secrets, fcntl, html, subprocess
from pathlib import Path
from typing import List
from fastapi import FastAPI, Request, Form, Depends, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.templating import Jinja2Templates

SECRETS_FILE = Path("/etc/ipsec.secrets")
LOCK_FILE = Path("/var/lock/ikev2_panel.lock")
security = HTTPBasic()

PANEL_USER = os.getenv("PANEL_USER", "paneladmin")
PANEL_PASS = os.getenv("PANEL_PASS", "panel123")

app = FastAPI(title="IKEv2 User Panel")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

def auth(credentials: HTTPBasicCredentials = Depends(security)):
    u_ok = secrets.compare_digest(credentials.username, PANEL_USER)
    p_ok = secrets.compare_digest(credentials.password, PANEL_PASS)
    if not (u_ok and p_ok):
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="IKEv2 Panel"'})
    return True

def read_users() -> List[str]:
    if not SECRETS_FILE.exists():
        return []
    users=[]
    with open(SECRETS_FILE, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"): continue
            m = re.match(r'^([^:\s]+)\s*:\s*EAP\s+"', ln)
            if m:
                users.append(m.group(1))
    return sorted(set(users))

def write_users(eap_lines: List[str]):
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK_FILE, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        existing = []
        if SECRETS_FILE.exists():
            with open(SECRETS_FILE, "r", encoding="utf-8") as f:
                existing = f.readlines()
        keep = [ln for ln in existing if ': RSA ' in ln]
        keep += [l if l.endswith("\n") else l+"\n" for l in eap_lines]
        with open(SECRETS_FILE, "w", encoding="utf-8") as f:
            f.writelines(keep)
        fcntl.flock(lock, fcntl.LOCK_UN)
    try:
        subprocess.run(["systemctl","reload","strongswan-starter"], check=False)
    except Exception:
        pass

def sanitize_user(u: str) -> str:
    if not re.match(r'^[A-Za-z0-9_.-]{1,64}$', u):
        raise ValueError("Invalid username")
    return u

def build_eap_line(u: str, p: str) -> str:
    return f'{u} : EAP "{p.replace("\"","\\\"")}"'

@app.get("/", response_class=HTMLResponse)
def home(request: Request, _=Depends(auth)):
    return templates.TemplateResponse("index.html", {"request": request, "users": read_users()})

@app.post("/add", response_class=RedirectResponse)
def add_user(username: str = Form(...), password: str = Form(...), _=Depends(auth)):
    try:
        u = sanitize_user(username.strip())
        if len(password) < 4:
            raise ValueError("Password too short")
        preserved=[]
        if SECRETS_FILE.exists():
            with open(SECRETS_FILE,"r",encoding="utf-8") as f:
                for ln in f:
                    if ': EAP ' in ln:
                        m = re.match(r'^([^:\s]+)\s*:\s*EAP\s+"(.*)"\s*$', ln.strip())
                        if m and m.group(1)!=u:
                            preserved.append(ln.strip())
        preserved.append(build_eap_line(u, password))
        write_users(preserved)
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
        write_users(preserved)
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/?error={html.escape(str(e))}", status_code=303)

@app.get("/api/users", response_class=PlainTextResponse)
def api_users(_=Depends(auth)):
    return "\n".join(read_users())
PYAPP

mkdir -p "$APP_DIR/templates"
cat >"$APP_DIR/templates/index.html"<<'HTML'
<!doctype html>
<html>
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IKEv2 User Panel</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:0;padding:24px;background:#0b1020;color:#e8eefc}
.card{max-width:760px;margin:0 auto;background:#141b34;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.25);padding:20px}
h1{margin:0 0 16px;font-size:22px}
.row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
input,button{padding:10px 12px;border-radius:10px;border:1px solid #2a335a;background:#0f1630;color:#e8eefc}
button{cursor:pointer;border:0;background:#2f80ed}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{padding:10px;border-bottom:1px solid #2a335a}
.muted{opacity:.8;font-size:13px}
.danger{background:#e74c3c}
</style>
</head>
<body>
  <div class="card">
    <h1>IKEv2 User Panel</h1>
    <div class="muted">Basic-auth protected. Changes reload strongSwan automatically.</div>

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
          <tr><td colspan="2" class="muted">No users.</td></tr>
        {% endif %}
      </tbody>
    </table>

    <p class="muted">API: <code>GET /api/users</code></p>
  </div>
</body>
</html>
HTML

echo "[7/10] Panel service"
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

systemctl daemon-reload
systemctl enable "${SYSTEMD_UNIT}"
systemctl restart "${SYSTEMD_UNIT}"

echo "[8/10] Verify services"
systemctl --no-pager --full status strongswan-starter || true
systemctl --no-pager --full status "${SYSTEMD_UNIT}" || true
systemctl --no-pager --full status apache2 || true

echo "[9/10] Quick server cert check"
echo "SubjectAltName of server cert:"
openssl x509 -in "$IPSEC_DIR/certs/ikev2-server.crt.pem" -noout -ext subjectAltName || true

echo "[10/10] Done"
cat <<INFO

===================== INFO =====================
Panel URL     : http://${SERVER_IP}:${PANEL_PORT}
Panel Auth    : ${PANEL_USER} / ${PANEL_PASS}
CA download   : http://${SERVER_IP}/IKEv2_CA.crt.pem
Secrets file  : ${SECRETS_FILE}
Server ID     : ${SERVER_ID}  (Use this exact IP/DNS on the phone)
Users now     : $(awk '/: EAP /{print $1}' ${SECRETS_FILE} 2>/dev/null | xargs echo)
------------------------------------------------
Android profile:
  Type: IKEv2 EAP (username/password)
  Server: ${SERVER_ID}
  CA   : IKEv2_CA.crt.pem (install this on device)
  User : ${VPN_USER_DEFAULT}
  Pass : ${VPN_PASS_DEFAULT}
------------------------------------------------
Change panel creds later:
  sed -i 's/^PANEL_USER=.*/PANEL_USER=newuser/' ${ENV_FILE}
  sed -i 's/^PANEL_PASS=.*/PANEL_PASS=newpass/' ${ENV_FILE}
  systemctl restart ${SYSTEMD_UNIT}

Security note: after downloading the CA, you can remove the public copy:
  rm -f /var/www/html/IKEv2_CA.crt.pem && systemctl restart apache2
================================================
INFO
