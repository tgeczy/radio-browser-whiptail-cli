#!/usr/bin/env python3
# Radio Browser CLI with whiptail menus, proper TTY wiring, clean labels,
# Play/Stop + status/PID, vote counts, AUDIO SETTINGS, and VLC per-process volume.
# Audio defaults: Pulse (if available) else ALSA "default" (no card index).
# Per-machine ALSA overrides are stored under /etc/machine-id so copying to other Pis won't break.
# Favorites: ~/.local/share/radio-browser/favorites.json
# Config:    ~/.local/share/radio-browser/config.json
#
# What’s new for Tomi:
# - VLC volume via RC over TCP + RC over UNIX socket + HTTP fallback.
# - Works over SSH and desktop. We use --ignore-config so user vlcrc won’t spawn the Lua CLI that quits VLC.
# - Test tone no longer “looks like an error” when it ends.
# - Fixed flow_search() arg mismatch.
# - Fixed pass_fds TypeError by passing a tuple (out.fileno(),).

from __future__ import annotations
import argparse
import atexit
import base64
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import requests
except ImportError:
    print("Missing 'requests'. Install with: sudo apt-get install -y python3-requests")
    sys.exit(1)

# ---------- constants, env, files ----------
APP_UA = os.environ.get("RB_UA", "radio-browser-cli/1.4 (tomi)")
BASE_CANDIDATES = [
    os.environ.get("RB_BASE"),
    "https://de1.api.radio-browser.info",
    "https://nl1.api.radio-browser.info",
    "https://all.api.radio-browser.info",
]

TEXT_MENU = os.getenv("RB_TEXT_MENU") == "1"  # set to 1 to force numbered prompts

RB_PLAYER = os.getenv("RB_PLAYER", "").strip().lower() or None  # mpv|cvlc|vlc
RB_AUDIO  = os.getenv("RB_AUDIO",  "auto").strip().lower()      # pulse|alsa|pipewire|auto
RB_ALSA_DEVICE_ENV = os.getenv("RB_ALSA_DEVICE", "").strip()    # e.g., plughw:2,0

DATA_DIR   = Path(os.environ.get("RB_DATA_DIR", str(Path.home() / ".local/share/radio-browser")))
FAV_FILE   = DATA_DIR / "favorites.json"
CONF_FILE  = DATA_DIR / "config.json"
PLAYER_LOG = DATA_DIR / "player.log"
SESSION_FILE = DATA_DIR / "session.json"
STOP_ON_EXIT = True
# VLC control endpoints
RC_SOCK          = DATA_DIR / "vlc-rc.sock"      # UNIX socket for rc/oldrc
RC_TCP_HOST      = "127.0.0.1"
RC_TCP_PORT: int = 0                              # chosen per run
HTTP_PORT: int   = 0                              # chosen per run
HTTP_PASS: str   = ""                             # random per run

# volume step (percent)
VLC_VOLSTEP_PCT = max(1, min(50, int(os.getenv("RB_VLC_VOLSTEP", "5"))))
COUNTRY_NAME_BY_CODE: Dict[str, str] = {}  # filled by countries_codes()

DEFAULT_CONF = {
    "audio_backend": "auto",
    "alsa_device": "default",
    "player": "",
    "per_host": {}  # { "<machine-id>": {"alsa_device": "plughw:2,0"} }
}

PLAY_PROC: Optional[subprocess.Popen] = None
NOW_PLAYING_NAME: Optional[str] = None
NOW_PLAYING_UUID: Optional[str] = None   
NOW_PLAYING_URL: Optional[str] = None   
CAST_MODE: str = "none"               # "none", "http", "chromecast_ip"
CAST_HTTP_NAME: Optional[str] = None  # last selected HTTP renderer name
CAST_HTTP_ID: Optional[int] = None    # last selected HTTP renderer id (best effort)
CAST_CC_IP: Optional[str] = None      # last Chromecast IP (Avahi path)
CAST_CC_NAME: Optional[str] = None
PLAY_PID: Optional[int] = None
# ---------- small utils ----------
def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not FAV_FILE.exists():
        FAV_FILE.write_text("[]", encoding="utf-8")
    if not CONF_FILE.exists():
        CONF_FILE.write_text(json.dumps(DEFAULT_CONF, indent=2), encoding="utf-8")

def load_favorites() -> List[Dict[str, str]]:
    ensure_data_dir()
    try:
        items = json.loads(FAV_FILE.read_text(encoding="utf-8"))
        return items if isinstance(items, list) else []
    except Exception:
        return []

def save_favorites(items: List[Dict[str, str]]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    FAV_FILE.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")

def fav_add(uuid: str, name: str) -> bool:
    """Add (uuid, name) to favorites.json if not present. Returns True if added."""
    items = load_favorites()
    for it in items:
        if it.get("uuid") == uuid:
            return False  # already present
    items.append({"uuid": uuid, "name": name})
    save_favorites(items)
    return True

def fav_remove(uuid: str) -> bool:
    """Remove uuid from favorites.json. Returns True if something was removed."""
    items = load_favorites()
    new_items = [i for i in items if i.get("uuid") != uuid]
    if len(new_items) == len(items):
        return False  # nothing to remove
    save_favorites(new_items)
    return True

def load_config() -> Dict[str, Any]:
    ensure_data_dir()
    try:
        cfg = json.loads(CONF_FILE.read_text(encoding="utf-8"))
        if not isinstance(cfg, dict):
            raise ValueError("bad config")
    except Exception:
        cfg = {}
    merged = DEFAULT_CONF | cfg
    if "per_host" not in merged or not isinstance(merged["per_host"], dict):
        merged["per_host"] = {}
    return merged

def save_config(cfg: Dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONF_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")

def have_cmd(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def in_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()

def host_id() -> str:
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            t = Path(p).read_text(encoding="utf-8").strip()
            if t:
                return t
        except Exception:
            pass
    return os.uname().nodename

def find_free_tcp_port(start: int, end: int) -> int:
    for port in range(start, end + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((RC_TCP_HOST, port))
            return port
        except OSError:
            pass
        finally:
            try: s.close()
            except: pass
    return 49212

# ---------- radio-browser API ----------
def sess() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": APP_UA, "Accept": "application/json"})
    return s

def pick_base(s: requests.Session) -> str:
    for base in BASE_CANDIDATES:
        if not base:
            continue
        try:
            r = s.get(f"{base}/json/stats", timeout=6)
            if r.ok:
                return base
        except Exception:
            pass
    print("Could not reach any Radio Browser API mirror.")
    sys.exit(2)

def api_get(s: requests.Session, base: str, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    r = s.get(f"{base}{path}", params=params or {}, timeout=20)
    r.raise_for_status()
    return r.json()

def countries_codes(s: requests.Session, base: str) -> List[Dict[str, Any]]:
    """Return countries with full names and codes; also fill COUNTRY_NAME_BY_CODE."""
    items = api_get(s, base, "/json/countries")
    out: List[Dict[str, Any]] = []
    COUNTRY_NAME_BY_CODE.clear()
    for x in items:
        name = (x.get("name") or "").strip()
        code = (x.get("iso_3166_1") or x.get("code") or "").strip().upper()
        try:
            count = int(x.get("stationcount") or 0)
        except Exception:
            count = 0
        if name and code and count > 0:
            COUNTRY_NAME_BY_CODE[code] = name
            out.append({"name": name, "code": code, "stationcount": count})
    out.sort(key=lambda c: c["name"].casefold())
    return out

def states_for_country(s: requests.Session, base: str, code: str, limit: int = 5000) -> List[str]:
    """List states by scanning stations for a given country code. Reliable and filtered."""
    params = {
        "countrycode": (code or "").upper(),
        "hidebroken": "true",
        "order": "state",
        "limit": str(limit),
    }
    try:
        stations = api_get(s, base, "/json/stations/search", params=params)
    except Exception:
        return []
    states = {(st.get("state") or "").strip() for st in stations}
    return sorted([x for x in states if x], key=str.casefold)

def search_stations(
    s: requests.Session,
    base: str,
    *,
    name: Optional[str] = None,
    countrycode: Optional[str] = None,
    state: Optional[str] = None,
    limit: int = 200,
    order: str = "name",
    hidebroken: bool = True,
) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"limit": str(limit), "order": order}
    if hidebroken:
        params["hidebroken"] = "true"
    if name:
        params["name"] = name
    if countrycode:
        params["countrycode"] = countrycode.upper()
    if state:
        params["state"] = state
    stations = api_get(s, base, "/json/stations/search", params=params)
    stations.sort(key=lambda st: ((st.get("name") or "").casefold(), st.get("stationuuid","")))
    return stations

def click_station(s: requests.Session, base: str, uuid: str) -> Dict[str, Any]:
    return api_get(s, base, f"/json/url/{uuid}")

def vote_station(s: requests.Session, base: str, uuid: str) -> Dict[str, Any]:
    return api_get(s, base, f"/json/vote/{uuid}")

def get_station_votes(s: requests.Session, base: str, uuid: str) -> Optional[int]:
    data = api_get(s, base, "/json/stations/byuuid", params={"uuids": uuid})
    if isinstance(data, list) and data:
        try:
            return int(data[0].get("votes"))
        except Exception:
            return None
    return None

# ---------- UI helpers ----------
def have_whiptail() -> Optional[str]:
    for cmd in ("whiptail", "dialog"):
        if have_cmd(cmd):
            return cmd
    return None

def _tty_open():
    try:
        return open("/dev/tty", "rb+", buffering=0)
    except Exception:
        return None

def _run_whiptail_capture(args: List[str]) -> Tuple[int, str]:
    tool = have_whiptail()
    if not tool:
        return (2, "")
    tty = _tty_open()
    if tty is None:
        return (1, "")
    with tty, tempfile.TemporaryFile(mode="w+b") as out:
        args = list(args) + ["--output-fd", str(out.fileno())]
        p = subprocess.run(
            args,
            stdin=tty,
            stdout=tty,
            stderr=tty,
            pass_fds=(out.fileno(),),  # <-- fixed: must be a tuple
            text=False
        )
        out.seek(0)
        data = out.read().decode(errors="replace").strip()
        return (p.returncode, data)

def msgbox(title: str, text: str) -> None:
    tool = have_whiptail()
    if not in_tty() or not tool or TEXT_MENU:
        print(f"\n[{title}] {text}\n")
        return
    _run_whiptail_capture([tool, "--title", title, "--msgbox", text, "12", "74"])

def menu_prompt(title: str, prompt: str, choices: Sequence[Tuple[str, str]]) -> Optional[str]:
    tool = have_whiptail()
    if in_tty() and tool and not TEXT_MENU:
        cmd = [tool, "--title", title, "--menu", prompt, "20", "78", "15"]
        for tag, item in choices:
            label = (item or "").replace("\n", " ").strip()
            if len(label) > 200:
                label = label[:197] + "..."
            cmd.extend([tag, label])
        rc, picked = _run_whiptail_capture(cmd)
        return picked if rc == 0 and picked else None
    print(f"\n== {title} ==")
    print(prompt)
    for i, (tag, item) in enumerate(choices, 1):
        print(f" {i}. {item} [{tag}]")
    try:
        i = int(input("Choose number (or 0 to cancel): ").strip() or "0")
    except Exception:
        return None
    if i <= 0 or i > len(choices):
        return None
    return choices[i - 1][0]

def input_prompt(title: str, prompt: str, init: str = "") -> Optional[str]:
    tool = have_whiptail()
    if in_tty() and tool and not TEXT_MENU:
        rc, s = _run_whiptail_capture([tool, "--title", title, "--inputbox", prompt, "10", "70", init])
        return (s or "").strip() if rc == 0 else None
    try:
        return input(f"{title}: {prompt} [{init}] ").strip() or init
    except EOFError:
        return None

def format_station_label(st: Dict[str, Any]) -> str:
    name = (st.get("name") or "").strip()
    cc = (st.get("countrycode") or "").strip()
    state = (st.get("state") or "").strip()
    codec = (st.get("codec") or "").strip().upper()
    br = st.get("bitrate") or ""
    meta = " ".join([p for p in [cc, state if state else None, codec if codec else None, f"{br}kbps" if br else None] if p])
    return f"{name}" if not meta else f"{name} | {meta}"

def build_indexed_choices(
    items: Sequence[Any],
    value_of,
    label_of,
) -> Tuple[List[Tuple[str, str]], Dict[str, Any], Dict[str, str]]:
    choices: List[Tuple[str, str]] = []
    tag_to_value: Dict[str, Any] = {}
    tag_to_label: Dict[str, str] = {}
    for i, it in enumerate(items, 1):
        tag = str(i)
        label = label_of(it)
        choices.append((tag, label))
        tag_to_value[tag] = value_of(it)
        tag_to_label[tag] = label
    return choices, tag_to_value, tag_to_label

# ---------- audio helpers ----------
def list_alsa_devices() -> List[Tuple[str, str]]:
    out = subprocess.run(["aplay", "-l"], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        return []
    devices: List[Tuple[str, str]] = []
    for line in out.stdout.splitlines():
        m = re.match(r"^card\s+(\d+):\s*([^\s\[]+)\s*\[(.*?)\],\s*device\s+(\d+):\s*(.*?)\s*\[(.*?)\]", line)
        if not m:
            continue
        card = int(m.group(1))
        card_short = m.group(2)
        card_name = m.group(3)
        dev = int(m.group(4))
        dev_short = m.group(5)
        dev_name = m.group(6)
        devstr = f"plughw:{card},{dev}"
        label = f"card {card}: {card_name} ({card_short}), device {dev}: {dev_name} ({dev_short})"
        devices.append((devstr, label))
    return devices

def test_tone(device: str) -> Tuple[bool, str]:
    if not have_cmd("speaker-test"):
        return False, "speaker-test not found (install: sudo apt-get install -y alsa-utils)"
    cmd = ["speaker-test", "-D", device, "-t", "sine", "-f", "440", "-l", "1"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        ok = (p.returncode == 0)
        text = (p.stdout + "\n" + p.stderr).strip()
        return ok or bool(text), text or "Tone played."
    except subprocess.TimeoutExpired:
        return True, "Tone played (timeout while waiting for speaker-test to exit)."
    except Exception as e:
        return False, str(e)

def show_player_log(lines: int = 80) -> str:
    if not PLAYER_LOG.exists():
        return "(no player.log yet)"
    txt = PLAYER_LOG.read_text(errors="replace")
    parts = txt.splitlines()
    tail = "\n".join(parts[-lines:])
    return tail if tail.strip() else "(log empty)"

def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # process exists but not killable by us – consider it alive
        return True

def _session_read() -> Optional[Dict[str, Any]]:
    try:
        if not SESSION_FILE.exists():
            return None
        return json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None

def _session_write(pid: int, url: str, name: str, uuid: Optional[str] = None) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "pid": pid,
            "rc_tcp_port": RC_TCP_PORT,
            "rc_unix": str(RC_SOCK),
            "http_port": HTTP_PORT,
            "http_pass": HTTP_PASS,
            "url": url,
            "name": name,
            "uuid": uuid or globals().get("NOW_PLAYING_UUID"),
            "ts": int(time.time()),
        }
        SESSION_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

def _session_clear() -> None:
    try:
        SESSION_FILE.unlink()
    except Exception:
        pass

def adopt_existing_session() -> bool:
    """Load a previous VLC session (if alive) so the menu can control/stop it."""
    global RC_TCP_PORT, HTTP_PORT, HTTP_PASS, NOW_PLAYING_URL, NOW_PLAYING_NAME, NOW_PLAYING_UUID, PLAY_PID
    data = _session_read()
    if not data:
        return False

    RC_TCP_PORT = int(data.get("rc_tcp_port") or 0)
    HTTP_PORT   = int(data.get("http_port") or 0)
    HTTP_PASS   = str(data.get("http_pass") or "")
    NOW_PLAYING_URL  = str(data.get("url") or "") or None
    NOW_PLAYING_NAME = str(data.get("name") or "") or None
    NOW_PLAYING_UUID = str(data.get("uuid") or "") or None
    PLAY_PID = int(data.get("pid") or 0) or None

    # Is it really alive?
    # Prefer HTTP – if status answers, it’s running.
    if HTTP_PORT and vlc_http_status(timeout=0.25):
        return True

    # Else, RC sockets?
    if _rc_connect_unix(timeout=0.12) or _rc_connect_tcp(timeout=0.12):
        return True

    # Else, PID still around?
    if PLAY_PID and _pid_alive(PLAY_PID):
        return True

    # Stale session, clean it up.
    _session_clear()
    return False

def kill_session_if_alive() -> bool:
    """Try to stop a background VLC using the saved session (RC/HTTP/PID)."""
    global RC_TCP_PORT, HTTP_PORT, HTTP_PASS
    data = _session_read()
    if not data:
        return False

    # Temporarily adopt its endpoints
    old_tcp, old_http, old_pass = RC_TCP_PORT, HTTP_PORT, HTTP_PASS
    RC_TCP_PORT = int(data.get("rc_tcp_port") or 0)
    HTTP_PORT   = int(data.get("http_port") or 0)
    HTTP_PASS   = str(data.get("http_pass") or "")

    stopped = False
    # Best: RC shutdown (closes VLC)
    try:
        r = vlc_rc_send("shutdown", expect_reply=False)
        if r is not None:
            stopped = True
            time.sleep(0.5)
    except Exception:
        pass

    # If RC failed, try to kill by PID
    if not stopped:
        pid = int(data.get("pid") or 0)
        if pid:
            try:
                os.kill(pid, 15)
                stopped = True
                time.sleep(0.5)
            except Exception:
                pass

    # Restore our globals and clear session file
    RC_TCP_PORT, HTTP_PORT, HTTP_PASS = old_tcp, old_http, old_pass
    _session_clear()
    return stopped
# ---------- audio helpers ----------

def _pulse_available() -> bool:
    xdg = os.getenv("XDG_RUNTIME_DIR")
    if xdg and (Path(xdg) / "pulse" / "native").exists():
        return True
    uid = os.getuid()
    return Path(f"/run/user/{uid}/pulse/native").exists()

def _pipewire_available() -> bool:
    """
    Heuristics: PipeWire runtime socket or pw-* tools.
    Returns True if native PipeWire is likely available.
    """
    try:
        xdg = os.getenv("XDG_RUNTIME_DIR") or ""
        uid = os.getuid()
        candidates = [
            Path(xdg) / "pipewire-0",
            Path(xdg) / "pulse" / "native",           # pipewire-pulse shim
            Path(f"/run/user/{uid}/pipewire-0"),
            Path(f"/run/user/{uid}/pulse/native"),
        ]
        if any(p.exists() for p in candidates):
            return True
    except Exception:
        pass
    for cmd in ("pw-cli", "pw-play", "pw-record", "pipewire"):
        if have_cmd(cmd):
            return True
    return False

def _per_host_alsa_override(cfg: Dict[str, Any]) -> Optional[str]:
    hid = host_id()
    ph = cfg.get("per_host", {})
    d = (ph.get(hid, {}) or {}).get("alsa_device")
    if d in ("", None, "default"):
        return None
    return d

def _current_audio_backend(cfg: Dict[str, Any]) -> str:
    if RB_AUDIO in ("pulse", "alsa"):
        return RB_AUDIO
    return (cfg.get("audio_backend") or "auto").lower()

def _current_player(cfg: Dict[str, Any]) -> Optional[str]:
    return RB_PLAYER or (cfg.get("player") or None)

# ---------- VLC RC/HTTP helpers ----------
def _rc_connect_unix(timeout: float = 0.5):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(str(RC_SOCK))
        return s
    except Exception:
        return None

def discover_chromecast_avahi(timeout: float = 4.0) -> List[Dict[str, str]]:
    """
    Return a list of Chromecast-like devices discovered via Avahi.
    Each item: {"name": str, "ip": str, "port": str, "id": Optional[str]}.
    Requires: avahi-utils (avahi-browse).
    """
    if not have_cmd("avahi-browse"):
        return []

    # -p => parseable ; -r => resolve ; -t => terminate when done
    cmd = ["avahi-browse", "-prt", "_googlecast._tcp"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []

    if p.returncode != 0 or not p.stdout:
        return []

    devices: Dict[str, Dict[str, str]] = {}
    for line in p.stdout.splitlines():
        if not line or not line.startswith("="):
            continue
        # =;iface;proto;name;service;domain;hostname;address;port;txt...
        parts = line.split(";")
        if len(parts) < 9:
            continue
        _sig, _iface, _proto, name, service, domain, hostname, ip, port = parts[:9]
        ip = (ip or "").strip()
        port = (port or "").strip()
        if not ip or not port:
            continue  # skip entries without a resolved address/port

        txt_fields = parts[9:] if len(parts) > 9 else []
        dev_id = ""
        for t in txt_fields:
            if t.startswith("id="):
                dev_id = t[3:]
                break
        key = f"{name}|{ip}|{port}"
        devices[key] = {"name": name, "ip": ip, "port": port, "id": dev_id}

    # Sort by name (case-insensitive)
    return sorted(devices.values(), key=lambda d: d["name"].casefold())

def _rc_connect_tcp(timeout: float = 0.5):
    if not RC_TCP_PORT:
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((RC_TCP_HOST, RC_TCP_PORT))
        return s
    except Exception:
        return None

def vlc_rc_send(cmd: str, expect_reply: bool = False, timeout: float = 0.7) -> Optional[str]:
    msg = (cmd.strip() + "\n").encode("utf-8", "ignore")
    for connector in (_rc_connect_unix, _rc_connect_tcp):
        s = connector(timeout=timeout)
        if not s:
            continue
        try:
            s.sendall(msg)
            if not expect_reply:
                return ""
            s.settimeout(timeout)
            chunks: List[bytes] = []
            end = time.time() + timeout
            while time.time() < end:
                try:
                    c = s.recv(4096)
                except socket.timeout:
                    break
                if not c:
                    break
                chunks.append(c)
                if b"\n>" in c:
                    break
            return (b"".join(chunks)).decode("utf-8", "ignore")
        except Exception:
            pass
        finally:
            try: s.close()
            except: pass
    return None

# --- CASTING (Chromecast/UPnP) helpers over HTTP -----------------------------

def vlc_http_list_renderers(timeout: float = 1.2) -> List[Dict[str, Any]]:
    """Return a list of available renderers [{id:int, name:str, type:str, flags:int}, ...]."""
    if not HTTP_PORT:
        return []
    url = f"http://127.0.0.1:{HTTP_PORT}/requests/rd.json"
    try:
        r = requests.get(url, headers=vlc_http_auth_headers(), timeout=timeout)
        if not r.ok:
            return []
        data = r.json()
    except Exception:
        return []

    found: List[Dict[str, Any]] = []

    def collect(obj: Any):
        if isinstance(obj, dict):
            if "id" in obj and ("name" in obj or "display_name" in obj):
                found.append({
                    "id": int(obj.get("id")),
                    "name": str(obj.get("name") or obj.get("display_name") or f"Renderer {obj.get('id')}"),
                    "type": str(obj.get("type") or obj.get("renderer_type") or ""),
                    "flags": int(obj.get("flags") or obj.get("capabilities") or 0),
                })
            else:
                for v in obj.values():
                    collect(v)
        elif isinstance(obj, list):
            for v in obj:
                collect(v)

    collect(data)

    # dedupe by id, then sort by name for a predictable menu
    uniq: Dict[int, Dict[str, Any]] = {}
    for it in found:
        uniq[it["id"]] = it
    return sorted(uniq.values(), key=lambda x: x["name"].casefold())


def vlc_http_set_renderer(renderer_id: int) -> bool:
    """Select renderer by id (see rd.json). Use -1 to unset."""
    if not HTTP_PORT:
        return False
    url = f"http://127.0.0.1:{HTTP_PORT}/requests/status.xml"
    try:
        r = requests.get(url,
                         params={"command": "set_renderer", "id": str(int(renderer_id))},
                         headers=vlc_http_auth_headers(),
                         timeout=1.0)
        return r.ok
    except Exception:
        return False


def vlc_http_unset_renderer() -> bool:
    """Stop casting (go back to local output)."""
    return vlc_http_set_renderer(-1)

def vlc_http_in_play(input_url: str) -> bool:
    """Tell VLC to play a new URL in the same process (keeps current renderer)."""
    if not HTTP_PORT:
        return False
    url = f"http://127.0.0.1:{HTTP_PORT}/requests/status.xml"
    try:
        r = requests.get(url,
                         params={"command": "in_play", "input": input_url},
                         headers=vlc_http_auth_headers(),
                         timeout=1.2)
        return r.ok
    except Exception:
        return False

def vlc_http_set_renderer_by_name(name: str, tries: int = 3) -> bool:
    """Re-select renderer by display name (case-insensitive). Retries as discovery can lag."""
    if not (HTTP_PORT and name):
        return False
    for _ in range(max(1, int(tries))):
        lst = vlc_http_list_renderers(timeout=1.2)
        rid = None
        for it in lst:
            if (it.get("name") or "").strip().casefold() == name.strip().casefold():
                rid = int(it["id"])
                break
        if rid is not None:
            return vlc_http_set_renderer(rid)
        time.sleep(0.3)
    return False

def cast_menu() -> None:
    """Pick a casting target or stop casting. Works for both HTTP renderers and Avahi/Chromecast."""
    global CAST_MODE, CAST_HTTP_NAME, CAST_HTTP_ID, CAST_CC_IP, CAST_CC_NAME
    global NOW_PLAYING_URL, NOW_PLAYING_NAME, PLAY_PROC

    if not is_playing():
        msgbox("Cast", "Start playback first.")
        return
    if not NOW_PLAYING_URL:
        msgbox("Cast", "I don't have the current stream URL yet—start playback from the menu once.")
        return

    # Try VLC HTTP renderer list first
    renderers: List[Dict[str, Any]] = []
    if HTTP_PORT:
        for n in (1.0, 1.5, 2.0):
            renderers = vlc_http_list_renderers(timeout=n)
            if renderers:
                break
            time.sleep(0.2)

    # ---------- HTTP renderer path ----------
    if renderers:
        while True:
            hdr: List[Tuple[str, str]] = []
            if CAST_MODE != "none":
                current = (
                    CAST_HTTP_NAME if CAST_MODE == "http"
                    else (CAST_CC_NAME or CAST_CC_IP or "Chromecast")
                )
                hdr.append(("stopcast", f"Stop casting (back to local) — {current}"))

            choices: List[Tuple[str, str]] = hdr + [(str(it["id"]), it["name"]) for it in renderers]
            choices += [("rescan", "Rescan devices"), ("back", "Back")]

            pick = menu_prompt("Cast to device", "Pick a device.", choices)
            if pick in (None, "back"):
                return
            if pick == "rescan":
                time.sleep(0.5)
                renderers = vlc_http_list_renderers(timeout=2.0)
                continue
            if pick == "stopcast":
                # HTTP: unset; Avahi: restart locally
                if CAST_MODE == "http":
                    ok = vlc_http_unset_renderer()
                    if ok:
                        CAST_MODE = "none"
                        CAST_HTTP_NAME = None
                        CAST_HTTP_ID   = None
                    msgbox("Cast", "Returned to local output." if ok else "Could not stop casting.")
                    continue
                else:
                    # We were casting via Avahi/sout; restart VLC locally
                    saved_url  = NOW_PLAYING_URL
                    saved_name = NOW_PLAYING_NAME or "Stream"
                    stop_playback()
                    time.sleep(0.25)  # let the previous VLC settle before spawning a new one
                    CAST_MODE   = "none"
                    CAST_CC_IP  = None
                    CAST_CC_NAME= None

                    if saved_url:
                        cfg = load_config()
                        proc, cmd, err = spawn_player(saved_url, saved_name, cfg)
                        if proc is None:
                            msg = "Stopped casting, but couldn't resume locally."
                            if err:
                                msg += f"\n{err}"
                            msg += f"\nSee log: {PLAYER_LOG}"
                            msgbox("Cast", msg)
                            return
                        PLAY_PROC = proc
                        NOW_PLAYING_NAME = saved_name
                        NOW_PLAYING_URL  = saved_url
                    msgbox("Cast", "Returned to local output.")
                    continue

            # Select a HTTP renderer and remember it
            ok = vlc_http_set_renderer(int(pick))
            if ok:
                CAST_MODE   = "http"
                CAST_HTTP_ID = int(pick)
                sel = next((it["name"] for it in renderers if str(it["id"]) == pick), None)
                CAST_HTTP_NAME = sel or "Renderer"
            msgbox("Cast", "Casting started." if ok else "Could not start casting.")
        # (end HTTP path)

    # ---------- Avahi/Chromecast fallback ----------
    cc = discover_chromecast_avahi(timeout=4.0)
    while True:
        choices: List[Tuple[str, str]] = []
        if CAST_MODE != "none":
            cur = CAST_CC_NAME or CAST_HTTP_NAME or CAST_CC_IP or "Renderer"
            choices.append(("stopcast", f"Stop casting (back to local) — {cur}"))

        if not cc:
            choices += [("rescan", "Rescan"), ("back", "Back")]
            pick = menu_prompt("Cast to device",
                               "No devices found. Make sure targets are on and on the same network.",
                               choices)
            if pick in (None, "back"):
                return
            if pick == "rescan":
                time.sleep(1)
                cc = discover_chromecast_avahi(timeout=5.0)
                continue
            if pick == "stopcast":
                # Same as HTTP branch: stop Avahi cast and resume locally
                saved_url  = NOW_PLAYING_URL
                saved_name = NOW_PLAYING_NAME or "Stream"
                stop_playback()
                time.sleep(0.25)  # let the previous VLC settle before spawning a new one
                CAST_MODE   = "none"
                CAST_CC_IP  = None
                CAST_CC_NAME= None
                if saved_url:
                    cfg = load_config()
                    proc, cmd, err = spawn_player(saved_url, saved_name, cfg)
                    if proc is None:
                        msg = "Stopped casting, but couldn't resume locally."
                        if err:
                            msg += f"\n{err}"
                        msg += f"\nSee log: {PLAYER_LOG}"
                        msgbox("Cast", msg)
                        return
                    PLAY_PROC = proc
                    NOW_PLAYING_NAME = saved_name
                    NOW_PLAYING_URL  = saved_url
                msgbox("Cast", "Returned to local output.")
                continue

        else:
            for it in cc:
                label = it["name"]
                if it.get("id"):
                    label += f" [{it['id']}]"
                label += f" ({it['ip']})"
                choices.append((it["ip"], label))
            choices += [("rescan", "Rescan devices"), ("back", "Back")]

            pick = menu_prompt("Cast to device", "Pick a device.", choices)
            if pick in (None, "back"):
                return
            if pick == "rescan":
                time.sleep(1)
                cc = discover_chromecast_avahi(timeout=5.0)
                continue
            if pick == "stopcast":
                saved_url  = NOW_PLAYING_URL
                saved_name = NOW_PLAYING_NAME or "Stream"
                stop_playback()
                time.sleep(0.25)  # let the previous VLC settle before spawning a new one
                CAST_MODE   = "none"
                CAST_CC_IP  = None
                CAST_CC_NAME= None
                if saved_url:
                    cfg = load_config()
                    proc, cmd, err = spawn_player(saved_url, saved_name, cfg)
                    if proc is None:
                        msg = "Stopped casting, but couldn't resume locally."
                        if err:
                            msg += f"\n{err}"
                        msg += f"\nSee log: {PLAYER_LOG}"
                        msgbox("Cast", msg)
                        return
                    PLAY_PROC = proc
                    NOW_PLAYING_NAME = saved_name
                    NOW_PLAYING_URL  = saved_url
                msgbox("Cast", "Returned to local output.")
                continue

            # Launch a dedicated Chromecast VLC for the chosen IP
            saved_url  = NOW_PLAYING_URL
            saved_name = NOW_PLAYING_NAME or "Stream"
            stop_playback()
            cfg = load_config()
            proc, cmd, err = spawn_player_chromecast(saved_url, saved_name, pick, cfg)
            if proc is None:
                msg = "Could not start casting."
                if err:
                    msg += f"\n{err}"
                msg += f"\nSee log: {PLAYER_LOG}"
                msgbox("Cast", msg)
                return

            PLAY_PROC = proc
            NOW_PLAYING_URL  = saved_url
            NOW_PLAYING_NAME = saved_name
            CAST_MODE  = "chromecast_ip"
            CAST_CC_IP = pick
            try:
                nm = next((it["name"] for it in cc if it.get("ip") == pick), None)
            except Exception:
                nm = None
            CAST_CC_NAME = nm or pick
            msgbox("Cast", f"Casting to {CAST_CC_NAME or pick}.")
            return

def _parse_volume_any(text: str) -> Optional[int]:
    if not text:
        return None
    m = re.search(r"(?i)\bvol(?:ume)?[^0-9]{0,8}(\d{1,4})\b", text)
    if m:
        return max(0, min(512, int(m.group(1))))
    m = re.search(r"<volume>(\d{1,4})</volume>", text)
    if m:
        return max(0, min(512, int(m.group(1))))
    return None

def vlc_http_auth_headers() -> Dict[str, str]:
    if not (HTTP_PORT and HTTP_PASS):
        return {}
    token = base64.b64encode(f":{HTTP_PASS}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}

def vlc_http_status(timeout: float = 0.8) -> Optional[str]:
    if not HTTP_PORT:
        return None
    url = f"http://127.0.0.1:{HTTP_PORT}/requests/status.xml"
    try:
        r = requests.get(url, headers=vlc_http_auth_headers(), timeout=timeout)
        return r.text if r.ok else None
    except Exception:
        return None

def vlc_http_volume_relative(delta_pct: int) -> bool:
    if not HTTP_PORT or delta_pct == 0:
        return False
    sign = "+" if delta_pct > 0 else "-"
    url = f"http://127.0.0.1:{HTTP_PORT}/requests/status.xml"
    try:
        r = requests.get(url, params={"command": "volume", "val": f"{sign}{abs(int(delta_pct))}%"},
                         headers=vlc_http_auth_headers(), timeout=0.9)
        return r.ok
    except Exception:
        return False

def vlc_get_volume_raw() -> Optional[int]:
    r = vlc_rc_send("status", expect_reply=True)
    v = _parse_volume_any(r or "")
    if v is not None:
        return v
    r = vlc_rc_send("volume", expect_reply=True)
    v = _parse_volume_any(r or "")
    if v is not None:
        return v
    t = vlc_http_status()
    if t:
        return _parse_volume_any(t)
    return None

def vlc_set_volume_raw(raw: int) -> bool:
    raw = max(0, min(512, int(raw)))
    r = vlc_rc_send(f"volume {raw}", expect_reply=True)
    if r is not None:
        return True
    # HTTP fallback (works for both 0..512 and 0..256 servers)
    return vlc_http_set_volume_raw(raw)

def vlc_adjust_volume_percent(delta_pct: int) -> Optional[int]:
    """Step volume by a fixed percentage of max (0..100), consistently across UIs."""
    try:
        delta_pct = int(delta_pct)
    except Exception:
        delta_pct = VLC_VOLSTEP_PCT if delta_pct >= 0 else -VLC_VOLSTEP_PCT

    # Convert percentage step to VLC's raw 0..512 scale
    delta_raw = int(round(delta_pct * 512 / 100))
    if delta_raw == 0:
        delta_raw = 1 if delta_pct > 0 else -1

    cur = vlc_get_volume_raw()

    # Preferred: precise target set (cur + delta)
    if cur is not None:
        tgt = max(0, min(512, cur + delta_raw))
        if vlc_set_volume_raw(tgt):
            v2 = vlc_get_volume_raw()
            return int(round((v2 if v2 is not None else tgt) * 100 / 512))
        # fall through to relative fallbacks only if direct set failed

    # Fallbacks (when we can't read/set the raw value directly)
    if vlc_http_volume_relative(delta_pct):
        time.sleep(0.12)
        v2 = vlc_get_volume_raw()
        return int(round(v2 * 100 / 512)) if v2 is not None else None

    sent = vlc_rc_send(("volup" if delta_pct > 0 else "voldown") + f" {abs(delta_raw)}", expect_reply=False)
    if sent is not None:
        time.sleep(0.12)
        v2 = vlc_get_volume_raw()
        return int(round(v2 * 100 / 512)) if v2 is not None else None

    return None

# --- VLC HTTP helpers (drop-in) ---

def vlc_http_get_volume_raw() -> Optional[int]:
    """Return VLC raw volume from HTTP status.xml, or None if not available."""
    port = globals().get("HTTP_PORT")
    passwd = globals().get("HTTP_PASS")
    if not port or not passwd:
        return None
    try:
        r = requests.get(f"http://127.0.0.1:{port}/requests/status.xml",
                         auth=("", str(passwd)), timeout=0.5)
        if not r.ok:
            return None
        m = re.search(r"<volume>(\d+)</volume>", r.text)
        if not m:
            return None
        return int(m.group(1))
    except Exception:
        return None

def vlc_http_set_volume_raw(raw: int) -> bool:
    """Set VLC raw volume via HTTP. Tries once with given raw, then a halved fallback for 512→256 scale."""
    port = globals().get("HTTP_PORT")
    passwd = globals().get("HTTP_PASS")
    if not port or not passwd:
        return False
    def _set(val: int) -> bool:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/requests/status.xml",
                             params={"command": "volume", "val": str(max(0, val))},
                             auth=("", str(passwd)), timeout=0.5)
            return r.ok
        except Exception:
            return False
    # try as-is
    if _set(raw):
        time.sleep(0.1)
        v = vlc_http_get_volume_raw()
        if v is not None and (v == 0 or v > 0):
            return True
    # scale fallback (handles HTTP expecting 0..256 when we stored 0..512)
    half = max(0, raw // 2)
    if half != raw and _set(half):
        time.sleep(0.1)
        v = vlc_http_get_volume_raw()
        return v is not None
    return False

# --- VLC RC helpers (drop-in) ---

def vlc_rc_get_volume_raw() -> Optional[int]:
    """Return VLC raw volume by asking RC 'status'."""
    resp = vlc_rc_send("status", expect_reply=True)
    if not resp:
        return None
    m = re.search(r"volume:\s*(\d+)", resp)
    return int(m.group(1)) if m else None

def vlc_rc_set_volume_raw(raw: int) -> bool:
    """Set VLC raw volume via RC. RC scale is 0..512."""
    ok = vlc_rc_send(f"volume {max(0, int(raw))}")
    if ok is None:
        return False
    time.sleep(0.1)
    v = vlc_rc_get_volume_raw()
    return v is not None

def vlc_toggle_mute() -> bool:
    """
    Reliable mute: set volume to 0, and on next toggle restore the last non-zero volume.
    Prefers HTTP; falls back to RC. Stores last non-zero raw in a module-global.
    """
    # read current volume (HTTP first)
    v = vlc_http_get_volume_raw()
    use_http = v is not None
    if v is None:
        v = vlc_rc_get_volume_raw()

    if v is None:
        return False

    # stash/restore across calls without requiring a separate global definition
    prev_raw = globals().get("LAST_NONZERO_VOL_RAW")

    if v > 0:
        # store and mute
        globals()["LAST_NONZERO_VOL_RAW"] = v
        if use_http:
            ok = vlc_http_set_volume_raw(0)
        else:
            ok = vlc_rc_set_volume_raw(0)
        return bool(ok)
    else:
        # currently muted; restore to previous or 50% (256 on 0..512, 128 on 0..256)
        target = prev_raw if isinstance(prev_raw, int) and prev_raw > 0 else 256
        if use_http:
            ok = vlc_http_set_volume_raw(target)
        else:
            ok = vlc_rc_set_volume_raw(target)

        return bool(ok)
def wait_for_vlc_interfaces(max_wait: float = 3.0) -> None:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        s = _rc_connect_unix(timeout=0.12)
        if s:
            try: s.close()
            except: pass
            return
        s2 = _rc_connect_tcp(timeout=0.12)
        if s2:
            try: s2.close()
            except: pass
            return
        if vlc_http_status(timeout=0.25):
            return
        time.sleep(0.05)

# ---------- player spawn ----------
def is_playing() -> bool:
    if PLAY_PROC is not None and PLAY_PROC.poll() is None:
        return True
    # Background VLC from a previous run?
    if HTTP_PORT and vlc_http_status(timeout=0.2):
        return True
    if _rc_connect_unix(timeout=0.12) or _rc_connect_tcp(timeout=0.12):
        return True
    return False

def stop_playback() -> None:
    global PLAY_PROC, PLAY_PID, NOW_PLAYING_NAME, NOW_PLAYING_UUID, NOW_PLAYING_URL
    global CAST_MODE, CAST_HTTP_NAME, CAST_HTTP_ID, CAST_CC_IP, CAST_CC_NAME

    killed = False
    if PLAY_PROC and PLAY_PROC.poll() is None:
        try:
            PLAY_PROC.terminate()
            PLAY_PROC.wait(timeout=2)
            killed = True
        except Exception:
            try:
                PLAY_PROC.kill()
                killed = True
            except Exception:
                pass
    else:
        # also try to stop a background session if we detached earlier
        killed = kill_session_if_alive()

    PLAY_PROC = None
    PLAY_PID = None
    NOW_PLAYING_NAME = None
    NOW_PLAYING_UUID = None
    NOW_PLAYING_URL  = None

    # clear casting state no matter how we were casting
    CAST_MODE = "none"
    CAST_HTTP_NAME = None
    CAST_HTTP_ID   = None
    CAST_CC_IP     = None
    CAST_CC_NAME   = None

    try:
        RC_SOCK.unlink()
    except Exception:
        pass

    if killed:
        _session_clear()

def _on_exit():
    if globals().get("STOP_ON_EXIT", True):
        stop_playback()
atexit.register(_on_exit)

def detect_players(cfg: Dict[str, Any]) -> List[str]:
    pref = _current_player(cfg)
    ordered: List[str] = []
    if pref and have_cmd(pref):
        ordered.append(pref)
    for p in ("cvlc", "vlc", "mpv"):
        if p not in ordered and have_cmd(p):
            ordered.append(p)
    return ordered


def build_attempts(url: str, cfg: Dict[str, Any]) -> List[List[str]]:
    attempts: List[List[str]] = []
    backend = _current_audio_backend(cfg)
    alsa_dev = RB_ALSA_DEVICE_ENV or _per_host_alsa_override(cfg)
    pulse_ok = _pulse_available()
    players = detect_players(cfg)

    def ao_args(p: str) -> List[List[str]]:
        arr: List[List[str]] = [[]]

        # pipewire (native) tries first, then pulse, then alsa
        if backend in ("pipewire", "auto") and _pipewire_available():
            if p == "mpv":
                # mpv native PipeWire
                arr.append(["--ao=pipewire", "--no-video"])
            elif p in ("vlc", "cvlc"):
                # Only try if VLC was built with pipewire aout; opt-in via env
                if os.getenv("RB_VLC_PIPEWIRE", "0") == "1":
                    arr.append(["--aout=pipewire"])

        if backend in ("pulse", "auto") and pulse_ok:
            arr.append(["--aout=pulse"] if p in ("vlc", "cvlc")
                       else ["--audio-device=pulse", "--no-video"])

        if backend in ("alsa", "auto"):
            if alsa_dev:
                arr.append(["--aout=alsa", "--alsa-audio-device", alsa_dev] if p in ("vlc", "cvlc")
                           else ["--ao=alsa", f"--audio-device=alsa/{alsa_dev}", "--no-video"])
            arr.append(["--aout=alsa"] if p in ("vlc", "cvlc") else ["--ao=alsa", "--no-video"])

        if p == "mpv":
            arr.append(["--no-video"])

        # dedupe
        uniq: List[List[str]] = []
        for a in arr:
            if a not in uniq:
                uniq.append(a)
        return uniq

    http1 = ["--extraintf", "http,mpris", "--http-host", "127.0.0.1",
             "--http-port", str(HTTP_PORT), "--http-password", HTTP_PASS]
    http2 = ["--extraintf", "http,mpris", "--http-host", "127.0.0.1",
             "--http-port", str(HTTP_PORT),
             "--lua-config", f"http={{password='{HTTP_PASS}'}}"]

    for p in players:
        if p in ("vlc", "cvlc"):
            rc_tcp = ["-I", "rc", "--rc-host", f"{RC_TCP_HOST}:{RC_TCP_PORT}"]
            for ao in ao_args(p):
                attempts.append([p, "--ignore-config"] + rc_tcp + http1 + ao + [url])
                attempts.append([p, "--ignore-config"] + rc_tcp + http2 + ao + [url])
            rc_un = ["-I", "oldrc", "--rc-fake-tty", "--rc-unix", str(RC_SOCK)]
            for ao in ao_args(p):
                attempts.append([p, "--ignore-config"] + rc_un + http1 + ao + [url])
                attempts.append([p, "--ignore-config"] + rc_un + http2 + ao + [url])
        elif p == "mpv":
            for ao in ao_args(p):
                attempts.append([p] + ao + [url])

    return attempts

def spawn_player(url: str, name: str, cfg: Dict[str, Any]) -> Tuple[Optional[subprocess.Popen], Optional[List[str]], Optional[str]]:
    global RC_TCP_PORT, HTTP_PORT, HTTP_PASS, PLAY_PID
    ensure_data_dir()
    try:
        RC_SOCK.unlink()
    except FileNotFoundError:
        pass

    RC_TCP_PORT = find_free_tcp_port(4212, 4230)
    HTTP_PORT   = find_free_tcp_port(18080, 18099)
    HTTP_PASS   = secrets.token_urlsafe(10)

    last_err: Optional[str] = None
    for cmd in build_attempts(url, cfg):
        try:
            with open(PLAYER_LOG, "ab", buffering=0) as log:
                log.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} attempt === ".encode())
                log.write((" ".join(cmd) + "\n").encode())
                proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            time.sleep(1.0)
            if proc.poll() is None:
                with open(PLAYER_LOG, "ab", buffering=0) as log:
                    log.write(b"=== started === ")
                    log.write((" ".join(cmd) + "\n").encode())
                wait_for_vlc_interfaces(3.0)
                PLAY_PID = proc.pid
                _session_write(PLAY_PID, url, name)
                return proc, cmd, None
            else:
                last_err = f"player exited: {cmd} (code {proc.returncode})"
        except FileNotFoundError:
            last_err = f"player not found: {cmd[0]}"
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
    return None, None, last_err

def spawn_player_chromecast(url: str, name: str, ip: str, cfg: Dict[str, Any]) -> Tuple[Optional[subprocess.Popen], Optional[List[str]], Optional[str]]:
    """Start VLC casting to a specific device IP."""
    global RC_TCP_PORT, HTTP_PORT, HTTP_PASS, PLAY_PID
    ensure_data_dir()
    try:
        RC_SOCK.unlink()
    except FileNotFoundError:
        pass

    # --- early guards to avoid None in the argv list ---
    if not isinstance(ip, str) or not ip.strip():
        return None, None, "No Chromecast target IP given."
    if not isinstance(url, str) or not url.strip():
        return None, None, "No stream URL to cast."

    RC_TCP_PORT = find_free_tcp_port(4212, 4230)
    HTTP_PORT   = find_free_tcp_port(18080, 18099)
    HTTP_PASS   = secrets.token_urlsafe(10)

    # Prefer cvlc if available (no GUI), else vlc
    player = "cvlc" if have_cmd("cvlc") else "vlc"

    # Build command: RC (TCP), HTTP, Chromecast sout
    cmd: List[str] = [
        player, "--ignore-config",
        "-I", "rc", "--rc-host", f"{RC_TCP_HOST}:{RC_TCP_PORT}",
        "--extraintf", "http,mpris", "--http-host", "127.0.0.1",
        "--http-port", str(HTTP_PORT), "--http-password", HTTP_PASS,
        "--demux-filter=demux_chromecast",
        "--sout", "#chromecast",
        "--sout-chromecast-ip", ip.strip(),
        "--http-reconnect",
        "--sout-keep",
        url.strip(),
        "--network-caching=3000",
        "--file-caching=10000",
        "--sout-mux-caching=2000",
    ]

    last_err: Optional[str] = None
    try:
        with open(PLAYER_LOG, "ab", buffering=0) as log:
            log.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} chromecast === ".encode())
            # Safe join for logging only; argv itself is already all strings.
            log.write((" ".join(x if isinstance(x, str) else str(x) for x in cmd) + "\n").encode())
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        time.sleep(1.2)
        if proc.poll() is None:
            wait_for_vlc_interfaces(3.0)
            PLAY_PID = proc.pid
            _session_write(PLAY_PID, url.strip(), name)
            return proc, cmd, None
        else:
            last_err = f"player exited: {cmd} (code {proc.returncode})"
    except Exception as e:
        last_err = f"{type(e).__name__}: {e}"
    return None, None, last_err

# ---------- flows ----------
def main_menu(s: requests.Session, base: str) -> None:
    cfg = load_config()
    while True:
        alsa_ovr = _per_host_alsa_override(cfg)
        alsa_show = alsa_ovr if alsa_ovr else "(auto)"
        backend = _current_audio_backend(cfg)
        items: List[Tuple[str, str]] = [
            ("browse", "Browse by country / state"),
            ("search", "Search by name"),
            ("favs",   "Favorites"),
            ("audio",  f"Audio settings  [backend: {backend}  ALSA: {alsa_show}]"),
            ("log",    "Player log (last lines)"),
        ]
        if is_playing():
            pid = PLAY_PROC.pid if PLAY_PROC else (PLAY_PID or 0)
            now = NOW_PLAYING_NAME or "Stream"
            vol_raw = vlc_get_volume_raw()
            if vol_raw is not None:
                v = int(round(vol_raw * 100 / 512))
                items.insert(0, ("status", f"Now playing: {now} (pid {pid})  Vol: {v}%"))
            else:
                items.insert(0, ("status", f"Now playing: {now} (pid {pid})"))
            items.extend([
                ("cast",  "Cast to network device"),
                ("vol+",  f"Volume up (+{VLC_VOLSTEP_PCT}%)"),
                ("vol-",  f"Volume down (-{VLC_VOLSTEP_PCT}%)"),
                ("mute",  "Mute/unmute"),
                ("detach","Detach & quit (keep playing)"),
                ("stop",  "Stop playback"),
            ])
        items.append(("quit", "Quit"))

        choice = menu_prompt("Radio Browser", "Use arrow keys + Enter. Esc cancels.", items)
        if choice is None or choice == "quit":
            return
        if choice == "browse":
            flow_by_country(s, base, cfg)
        elif choice == "search":
            flow_search(s, base, cfg)
        elif choice == "favs":
            flow_favorites(s, base, cfg)
        elif choice == "stop":
            stop_playback()
            msgbox("Player", "Playback stopped.")
        elif choice == "detach":
            globals()["STOP_ON_EXIT"] = False
            msgbox("Detach", "Quitting the menu; VLC keeps playing in the background.")
            raise SystemExit(0)
        elif choice == "status":
            info = f"Status: {'playing' if is_playing() else 'stopped'}\n"
            info += f"Backend: {backend}\n"
            info += f"ALSA override: {alsa_show}\n"
            if is_playing():
                pid = PLAY_PROC.pid if PLAY_PROC else (PLAY_PID or 0)
                info += f"PID: {pid}\n"
                v = vlc_get_volume_raw()
                if v is not None:
                    info += f"Volume: {int(round(v*100/512))}%\n"
            msgbox("Player", info.strip())
            if NOW_PLAYING_UUID:
                station_actions(s, base, NOW_PLAYING_UUID, cfg, preknown_name=NOW_PLAYING_NAME or "")
        elif choice == "log":
            msgbox("Player log", show_player_log())
        elif choice == "audio":
            cfg = audio_menu(cfg)
        elif choice == "cast":
            cast_menu()
        elif choice == "vol+":
            v = vlc_adjust_volume_percent(+VLC_VOLSTEP_PCT)
            msgbox("Volume", f"Raised to {v}%." if v is not None else "Volume: could not contact VLC.")
        elif choice == "vol-":
            v = vlc_adjust_volume_percent(-VLC_VOLSTEP_PCT)
            msgbox("Volume", f"Lowered to {v}%." if v is not None else "Volume: could not contact VLC.")
        elif choice == "mute":
            ok = vlc_toggle_mute()
            msgbox("Volume", "Mute toggled." if ok else "Mute: could not contact VLC.")

def audio_menu(cfg: Dict[str, Any]) -> Dict[str, Any]:
    while True:
        backend   = _current_audio_backend(cfg)
        alsa_ovr  = _per_host_alsa_override(cfg)
        alsa_show = alsa_ovr if alsa_ovr else "(auto)"
        cur_player = _current_player(cfg) or "auto"

        choices: List[Tuple[str, str]] = [
            ("backend", f"Audio backend: {backend}      (auto / pipewire / pulse / alsa)"),
            ("player",  f"Preferred player: {cur_player}  (auto/mpv/cvlc/vlc)"),
            ("test",    "Test tone (1s, 440Hz)  — uses ALSA override or default"),
            ("back",    "Back"),
        ]
        # Only show ALSA override if backend is not 'pulse' or 'pipewire'
        if backend not in ("pulse", "pipewire"):
            choices.insert(1, ("device",  f"ALSA device override (this machine): {alsa_show}"))

        c = menu_prompt("Audio settings", "Pick an option.", choices)
        if c in (None, "back"):
            return cfg
        if c == "backend":
            opts = [("auto","auto")]
            if _pipewire_available():  # offer only if present
                opts.append(("pipewire","pipewire"))
            opts.extend([("pulse","pulse"), ("alsa","alsa")])
            b = menu_prompt("Audio backend", "Choose:", opts)
            if b:
                cfg["audio_backend"] = b
                save_config(cfg)
        elif c == "device":
            devs = list_alsa_devices()
            items: List[Tuple[str, str]] = [("auto", "Auto (system default)")]
            items += [(d, lbl) for (d, lbl) in devs]
            pick = menu_prompt("ALSA device (this machine)", "Choose output device.", items)
            if pick is None:
                continue
            hid = host_id()
            cfg.setdefault("per_host", {})
            if pick == "auto":
                if hid in cfg["per_host"]:
                    cfg["per_host"][hid].pop("alsa_device", None)
                    if not cfg["per_host"][hid]:
                        cfg["per_host"].pop(hid, None)
            else:
                cfg["per_host"].setdefault(hid, {})["alsa_device"] = pick
            save_config(cfg)
        elif c == "player":
            opts = [("","auto")]
            for p in ("mpv","cvlc","vlc"):
                if have_cmd(p):
                    opts.append((p,p))
            pick = menu_prompt("Preferred player", "Choose player.", opts)
            if pick is not None:
                cfg["player"] = pick
                save_config(cfg)
        elif c == "test":
            dev = alsa_ovr or "default"
            ok, text = test_tone(dev)
            msgbox("Test tone" if ok else "Test tone (note)", text if text.strip() else ("OK" if ok else "Note"))

# ---------- flows ----------

def flow_by_country(s: requests.Session, base: str, cfg: Dict[str, Any]) -> None:
    countries = countries_codes(s, base)  # now returns [{name, code, stationcount}]
    choices, tag_to_country, _ = build_indexed_choices(
        countries,
        value_of=lambda c: {"name": c["name"], "code": c["code"]},
        label_of=lambda c: f"{c['name']} [{c['code']}] ({c.get('stationcount','0')})",
    )
    tag = menu_prompt("Countries", "Pick a country.", choices + [("0", "Back")])
    if tag in (None, "0"):
        return

    picked = tag_to_country[tag]
    country_name = picked["name"]
    cc = picked["code"]

    # Stay inside this country until the user backs to the countries menu
    while True:
        states = states_for_country(s, base, cc)
        if states:
            st_choices, tag_to_state, _ = build_indexed_choices(
                [None] + states,
                value_of=lambda x: None if x is None else x,
                label_of=lambda x: "All states" if x is None else x,
            )
            tag = menu_prompt(f"States in {country_name}", "Pick a state/region.", st_choices + [("0", "Back to countries")])
            if tag in (None, "0"):
                return
            state = tag_to_state[tag]
        else:
            state = None

        stations = search_stations(s, base, countrycode=cc, state=state, limit=500)
        if not stations:
            msgbox("Stations", f"No stations found for {country_name} [{cc}].")
            # Loop back to state picker (or reload the single-country view if no states)
            continue

        station_menu_loop(s, base, stations, cfg)
        # Back from stations -> show states again (same country)

def flow_search(s: requests.Session, base: str, cfg: Dict[str, Any]) -> None:
    name = input_prompt("Search", "Station name (substring):", "")
    if not name:
        return
    stations = search_stations(s, base, name=name, limit=200)
    if not stations:
        msgbox("Stations", "No stations found.")
        return
    station_menu_loop(s, base, stations, cfg)

def flow_favorites(s: requests.Session, base: str, cfg: Dict[str, Any]) -> None:
    items = load_favorites()
    if not items:
        msgbox("Favorites", "No favorites yet.")
        return
    while True:
        fav_choices, tag_to_uuid, tag_to_label = build_indexed_choices(
            items, value_of=lambda it: it["uuid"], label_of=lambda it: it["name"]
        )
        tag = menu_prompt("Favorites", "Pick a favorite.", fav_choices + [("0", "Back")])
        if tag in (None, "0"):
            return
        uuid = tag_to_uuid[tag]
        name = tag_to_label[tag]
        station_actions(s, base, uuid, cfg, preknown_name=name)

def station_menu_loop(s: requests.Session, base: str, stations: List[Dict[str, Any]], cfg: Dict[str, Any]) -> None:
    choices, tag_to_uuid, tag_to_label = build_indexed_choices(
        stations, value_of=lambda st: st.get("stationuuid",""), label_of=format_station_label
    )
    while True:
        tag = menu_prompt("Stations", "Pick a station.", choices + [("0", "Back")])
        if tag in (None, "0"):
            return
        uuid = tag_to_uuid.get(tag)
        if not uuid:
            continue
        label = tag_to_label.get(tag, "")
        name = label.split(" | ", 1)[0] if label else ""
        station_actions(s, base, uuid, cfg, preknown_name=name)

def station_actions(s: requests.Session, base: str, uuid: str, cfg: Dict[str, Any], preknown_name: str = "") -> None:
    """Actions for a single station, with favorites label that updates live."""
    global PLAY_PROC, NOW_PLAYING_NAME, NOW_PLAYING_UUID, NOW_PLAYING_URL, CAST_MODE, CAST_HTTP_NAME, CAST_HTTP_ID, CAST_CC_IP, CAST_CC_NAME
    while True:
        # live vote label
        votes = get_station_votes(s, base, uuid)
        vote_label = "Vote" if votes is None else f"Vote (current: {votes})"

        # check favorite state fresh each loop so the label updates
        favs = load_favorites()
        is_fav = any((it.get("uuid") == uuid) for it in favs)

        # build actions — show only one of Add/Remove
        actions: List[Tuple[str, str]] = [
            ("play",  "Play"),
            ("vote",  vote_label),
            ("fav" if not is_fav else "rmfav", "Add to favorites" if not is_fav else "Remove from favorites"),
            ("vol+",  f"Volume up (+{VLC_VOLSTEP_PCT}%)"),
            ("vol-",  f"Volume down (-{VLC_VOLSTEP_PCT}%)"),
            ("mute",  "Mute/unmute"),
("cast",  "Cast to network device"),
        ]
        if is_playing():
            actions.append(("stop", "Stop playback"))
        actions.append(("back", "Back"))

        act = menu_prompt(preknown_name or "Station", "Choose an action.", actions)
        if act in (None, "back"):
            return

        if act == "play":
            try:
                info = click_station(s, base, uuid)
                new_url = (info.get("url") or "").strip()
                if not new_url:
                    msgbox("Play", "Could not resolve stream URL.")
                    continue

                # --- Sticky casting logic ---
                # Case A: HTTP renderer already selected -> switch input in-place (no respawn)
                if CAST_MODE == "http" and HTTP_PORT:
                    if vlc_http_in_play(new_url):
                        NOW_PLAYING_NAME = preknown_name or "Stream"
                        NOW_PLAYING_UUID = uuid
                        NOW_PLAYING_URL  = new_url
                        pid = PLAY_PROC.pid if PLAY_PROC else (PLAY_PID or 0)
                        _session_write(pid, NOW_PLAYING_URL, NOW_PLAYING_NAME, uuid=NOW_PLAYING_UUID)
                        msgbox("Player", f"Switched stream on current renderer: {CAST_HTTP_NAME or 'Renderer'}.")
                        continue
                    # If in-place failed (rare), fall back to respawn and re-apply by name.

                # Case B: Avahi/Chromecast IP -> respawn in Chromecast mode to same device
                if CAST_MODE == "chromecast_ip" and CAST_CC_IP:
                    # Stash before stop_playback() wipes globals
                    target_ip   = CAST_CC_IP
                    target_name = CAST_CC_NAME

                    stop_playback()

                    proc, cmd, err = spawn_player_chromecast(
                        new_url,
                        preknown_name or "Stream",
                        target_ip,
                        cfg
                    )
                    if proc is None:
                        msg = "Could not start player (Chromecast)."
                        if err:
                            msg += f"\n{err}"
                        msg += f"\nSee log: {PLAYER_LOG}"
                        msgbox("Player", msg)
                        continue

                    PLAY_PROC = proc
                    NOW_PLAYING_NAME = preknown_name or "Stream"
                    NOW_PLAYING_UUID = uuid
                    NOW_PLAYING_URL  = new_url

                    # Re-apply cast state we intentionally wiped
                    CAST_MODE   = "chromecast_ip"
                    CAST_CC_IP  = target_ip
                    CAST_CC_NAME = target_name

                    _session_write(PLAY_PROC.pid, NOW_PLAYING_URL, NOW_PLAYING_NAME, uuid=NOW_PLAYING_UUID)
                    pid = PLAY_PROC.pid
                    exe = cmd[0] if cmd else "player"
                    msgbox("Player", f"Playing (cast): {NOW_PLAYING_NAME}\nPID: {pid}\nVia: {exe}")
                    continue

                # Case C: normal local playback (pulse/alsa). If we had an HTTP renderer,
                # respawn locally and re-apply the renderer by its name.
                stop_playback()
                time.sleep(0.25)  # let the previous VLC settle before spawning a new one
                proc, cmd, err = spawn_player(new_url, preknown_name or "Stream", cfg)
                if proc is None:
                    msg = "Could not start player."
                    if err:
                        msg += f"\n{err}"
                    msg += f"\nSee log: {PLAYER_LOG}"
                    msgbox("Player", msg)
                    continue

                PLAY_PROC = proc
                NOW_PLAYING_NAME = preknown_name or "Stream"
                NOW_PLAYING_UUID = uuid
                NOW_PLAYING_URL  = new_url
                _session_write(PLAY_PROC.pid, NOW_PLAYING_URL, NOW_PLAYING_NAME, uuid=NOW_PLAYING_UUID)
                pid = PLAY_PROC.pid
                exe = cmd[0] if cmd else "player"

                # If we had selected an HTTP renderer before, re-select it on the fresh VLC.
                if CAST_MODE == "http" and CAST_HTTP_NAME:
                    # wait_for_vlc_interfaces() already ran in spawn_player(); just re-apply
                    applied = vlc_http_set_renderer_by_name(CAST_HTTP_NAME, tries=4)
                    if applied:
                        msgbox("Player", f"Playing (cast): {NOW_PLAYING_NAME}\nPID: {pid}\nVia: {exe}")
                        continue  # already casting
                    # If re-apply failed, leave it playing locally but keep going.

                msgbox("Player", f"Playing: {NOW_PLAYING_NAME}\nPID: {pid}\nVia: {exe}")
            except Exception as e:
                msgbox("Play", f"Error: {e}")
            continue

        if act == "stop":
            stop_playback()
            msgbox("Player", "Playback stopped.")
            continue

        if act == "vote":
            try:
                res = vote_station(s, base, uuid)
                msg = res.get("message", "") or "Voted."
                new_votes = get_station_votes(s, base, uuid)
                if new_votes is not None:
                    msg += f"\nVotes now: {new_votes}"
                msgbox("Vote", msg)
            except Exception as e:
                msgbox("Vote", f"Error: {e}")
            continue

        if act == "fav":
            # add and report accurately
            name = preknown_name or uuid
            added = fav_add(uuid, name)
            msgbox("Favorites", "Added." if added else "Already in favorites.")
            continue  # refresh menu so label flips to "Remove from favorites"

        if act == "rmfav":
            removed = fav_remove(uuid)
            msgbox("Favorites", "Removed." if removed else "Was not in favorites.")
            continue  # refresh menu so label flips to "Add to favorites"

        if act == "vol+":
            v = vlc_adjust_volume_percent(+VLC_VOLSTEP_PCT)
            msgbox("Volume", f"Increased. {v}%." if v is not None else "Could not reach VLC control.")
            continue

        if act == "vol-":
            v = vlc_adjust_volume_percent(-VLC_VOLSTEP_PCT)
            msgbox("Volume", f"Decreased. {v}%." if v is not None else "Could not reach VLC control.")
            continue

        if act == "mute":
            ok = vlc_toggle_mute()
            msgbox("Volume", "Mute toggled." if ok else "Could not reach VLC control.")
            continue
        if act == "cast":
            cast_menu()
            continue
# ---------- plain printing for non-menu subcommands ----------
def print_stations_plain(stations: List[Dict[str, Any]]) -> None:
    for st in stations:
        uuid = st.get("stationuuid", "")
        name = (st.get("name") or "").strip()
        cc = (st.get("countrycode") or "").strip()
        state = (st.get("state") or "").strip()
        codec = (st.get("codec") or "").strip()
        bitrate = str(st.get("bitrate") or "")
        url = (st.get("url_resolved") or st.get("url") or "").strip()
        print("|".join([uuid, name, cc, state, codec, bitrate, url]))

# ---------- CLI ----------
# ---------- CLI ----------
def main(argv: Optional[List[str]] = None) -> int:
    global RC_TCP_PORT, HTTP_PORT, HTTP_PASS, NOW_PLAYING_NAME, NOW_PLAYING_UUID, NOW_PLAYING_URL
    parser = argparse.ArgumentParser(description="Radio Browser CLI (menus + favorites + VLC volume).")
    sub = parser.add_subparsers(dest="cmd")

    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["menu"]

    sub.add_parser("menu", help="Interactive arrow-key menu")

    bl = sub.add_parser("by-location", help="Print stations by country/state")
    bl.add_argument("--countrycode", "-c", required=True)
    bl.add_argument("--state")
    bl.add_argument("--limit", type=int, default=100)

    bn = sub.add_parser("by-name", help="Print stations by name")
    bn.add_argument("--name", "-n", required=True)
    bn.add_argument("--limit", type=int, default=100)

    ps = sub.add_parser("play-station", help="Play by station UUID")
    ps.add_argument("--uuid", required=True)
    ps.add_argument("--detach", action="store_true")

    pu = sub.add_parser("play-url", help="Play a raw stream URL")
    pu.add_argument("--url", required=True)
    pu.add_argument("--detach", action="store_true")

    args = parser.parse_args(argv)
    s = sess()
    base = pick_base(s)

    if args.cmd == "menu":
        ensure_data_dir()
        adopt_existing_session()  
        main_menu(s, base)
        return 0

    if args.cmd == "by-location":
        st = search_stations(s, base, countrycode=args.countrycode, state=args.state, limit=args.limit)
        print_stations_plain(st)
        return 0

    if args.cmd == "by-name":
        st = search_stations(s, base, name=args.name, limit=args.limit)
        print_stations_plain(st)
        return 0

    if args.cmd == "play-station":
        try:
            info = click_station(s, base, args.uuid)
            url = (info.get("url") or "").strip()
        except Exception as e:
            print(f"Could not resolve station URL: {e}", file=sys.stderr)
            return 3
        if not url:
            print("Could not resolve station URL", file=sys.stderr)
            return 3

        cfg = load_config()
        try:
            RC_SOCK.unlink()
        except Exception:
            pass

        RC_TCP_PORT = find_free_tcp_port(4212, 4230)
        HTTP_PORT   = find_free_tcp_port(18080, 18099)
        HTTP_PASS   = secrets.token_urlsafe(10)

        proc, cmd, err = spawn_player(url, f"UUID {args.uuid}", cfg)
        if proc is None:
            if err:
                print(err, file=sys.stderr)
            print(f"See log: {PLAYER_LOG}", file=sys.stderr)
            return 4
        NOW_PLAYING_NAME = f"UUID {args.uuid}"
        NOW_PLAYING_UUID = args.uuid
        NOW_PLAYING_URL  = url

        if args.detach:
            return 0
        return proc.wait()

    if args.cmd == "play-url":
        url = args.url
        cfg = load_config()
        try:
            RC_SOCK.unlink()
        except Exception:
            pass

        RC_TCP_PORT = find_free_tcp_port(4212, 4230)
        HTTP_PORT   = find_free_tcp_port(18080, 18099)
        HTTP_PASS   = secrets.token_urlsafe(10)

        proc, cmd, err = spawn_player(url, "URL", cfg)
        if proc is None:
            if err:
                print(err, file=sys.stderr)
            print(f"See log: {PLAYER_LOG}", file=sys.stderr)
            return 4
        NOW_PLAYING_NAME = "URL"
        NOW_PLAYING_UUID = None
        NOW_PLAYING_URL  = url

        if args.detach:
            return 0
        return proc.wait()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
