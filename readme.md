
# Radio-Browser CLI in Whiptail: A Cli package for the public Radio browser API, built to be lightweight , accessible and easy to use from the ground up. Linux only for now.

A TTY-friendly radio browser for Linux that:

* browses stations by **country/state** or **name**
* plays via **VLC** (or mpv for local playback only)
* has **favorites**, **audio settings**, **volume/mute** (VLC), **player log**
* can **cast to Chromecast** devices (via Avahi discovery or VLC HTTP renderers)
* works over **SSH** and on a local desktop
* keeps a tiny **session file** so you can re-attach to a backgrounded player

Designed with accessibility in mind (whiptail menus; also usable in plain text mode).

---

## Quick start

```bash
# 1) get the script
git clone https://github.com/tgeczy/radio-browser-whiptail-cli
cd radio-browser-whiptail-cli
chmod +x /src/radio_cli.py

# 2) install OS packages (Debian/Raspberry Pi OS examples)
sudo apt update
sudo apt install -y vlc avahi-daemon avahi-utils whiptail jq python3-requests

# 3) run it
src/radio_cli.py            # default opens the menu
```

> If `whiptail` isn’t available, the app falls back to numbered prompts.
> To force text prompts even if whiptail exists: `RB_TEXT_MENU=1 src/radio_cli.py`

---

## Features at a glance

* **Menu**: Browse by country/state, search by name, see favorites, adjust audio backend/device, read the player log. You can even play a loud test tone for yourself if you want to. 
* **Playback**: starts VLC with RC + HTTP control (no user vlcrc). Works in desktop (terminal) and over SSH.
* **Volume/mute**: exact control through VLC RC/HTTP (when VLC is the active local player, MPV is for basic playback).
* **Casting**:

  * **Avahi path** (reliable on Raspberry Pi): discovers `_googlecast._tcp` devices and casts via VLC’s Chromecast `sout`.
  * **VLC HTTP path** (if your VLC exposes it): uses `/requests/rd.json` + `set_renderer` to switch devices without respawn.
* **Favorites**: simple `favorites.json` file.
* **Session re-attach**: reopen the app and it will detect a running VLC and show status.

---

## Requirements

### OS packages (Debian/Raspberry Pi OS names)

* **VLC** (or **cvlc**): `sudo apt install -y vlc`
* **Avahi** (for Chromecast discovery): `sudo apt install -y avahi-daemon avahi-utils`
* **Whiptail** (menus): `sudo apt install -y whiptail`
  (If you prefer `dialog`, that works too.)
* **Python 3 requests**: `sudo apt install -y python3-requests`

Optional:

* **jq** (handy for debugging HTTP endpoints): `sudo apt install -y jq`
* **mpv** (local playback only; no casting): `sudo apt install -y mpv`
> Note on VLC builds: some distro builds *don’t* expose `/requests/rd.json`. In that case the app will still cast fine via the Avahi path (which respawns VLC with Chromecast flags).

---

## Files and folders

* Data dir: `~/.local/share/radio-browser/`

  * `favorites.json` — saved stations
  * `config.json` — audio backend, per-host ALSA override, preferred player
  * `player.log` — VLC stdout/stderr (very helpful)
  * `session.json` — current PID, ports, URL, UUID (used for re-attach)
* Per-machine ALSA overrides are keyed by `/etc/machine-id`.

---

## Environment variables

* `RB_TEXT_MENU=1` — force text prompts instead of whiptail.
* `RB_PLAYER` — prefer `cvlc`, `vlc`, or `mpv` (empty = auto).
* `RB_AUDIO` — `auto`, `pulse`, or `alsa`.
* `RB_ALSA_DEVICE` — e.g. `plughw:2,0` to pin a card/device.
* `RB_VLC_VOLSTEP` — volume step in percent (default `5`).
* `RB_UA` — custom HTTP User-Agent for Radio-Browser (optional).

---

## Command-line usage

All commands return plain output suitable for scripting. If you run with no args, you get the menu.

```text
./radio.py menu
    Launch interactive menu (default if no args)

./radio.py by-location --countrycode HU [--state "Budapest"] [--limit 500]
    Print stations for a country/state:
    stationuuid|name|CC|STATE|codec|bitrate|url

./radio.py by-name --name "Jazz" [--limit 200]
    Print stations matching a name substring.

./radio.py play-station --uuid <stationuuid> [--detach]
    Resolve the station’s stream URL via the API and play it in VLC.
    --detach: do not attach stdin/stdout; leaves VLC running in the background.

./radio.py play-url --url <http(s)://...> [--detach]
    Play a raw stream URL.

-h / --help
```

---

## Menu tips (keyboard)

* **Up/Down**, **Enter** to pick
* **Esc** to go back
* In text mode: enter the number shown
* From “Status”, pressing “OK” takes you to **Now Playing** for quick actions

---

## Audio settings

* **Audio backend**: `auto`, `pulse`, or `alsa`
* **ALSA device**: pick from detected cards (hidden when Pulse is set)
* **Preferred player**: `auto`, plus any of `cvlc`, `vlc`, `mpv` actually found on your system

  * mpv is supported for **local playback only**; casting and volume/mute controls are VLC-only.

---

## Casting notes

* If your VLC build exposes HTTP renderers, they will appear in the **Cast** menu and casting stays in the *same* VLC process.
* If not, you’ll still see devices found by **Avahi**. Picking one respawns VLC with:

  ```
  --demux-filter=demux_chromecast --sout '#chromecast' --sout-chromecast-ip <IP>
  ```
* For long radio sessions, we pass extra caching flags and keep the pipeline alive. It should only add at most a 2-second delay to real stream.

---

## Accessibility

* whiptail menus are concise and read well on screen readers.
* For a simpler prompt flow in any terminal: `RB_TEXT_MENU=1 ./radio.py`
* When building I really wanted the ease-of-use for text-based choice prompts but the flexibility of a menu alongside it. This gets us there!
---

## Troubleshooting

* **No devices in “HTTP renderers”**
  Your VLC likely doesn’t expose `/requests/rd.json`. Use the Avahi list; casting still works. If this still fails, make sure Avahi-utils is actually installed and shows on your system.

* **Cast stops after \~5 minutes**
  We already set `--demux-filter=demux_chromecast`, `--sout-keep`, and larger caches.

* **Pulse over SSH**
  If there’s no Pulse socket for the SSH user, the app will fall back to ALSA automatically.

* **Find the current HTTP port/password**
  See `~/.local/share/radio-browser/session.json`, or open “Debug → HTTP control info” in the menu.

* **Kill a stuck background VLC**
  The app tracks and stops its own PID. As a last resort:

  ```bash
  pkill -f 'vlc|cvlc'
  ```

---

## How it picks a player

1. Your **preferred player** (if installed)
2. Then, `cvlc` → `vlc` → `mpv`

   * VLC is required for VLC-specific features (volume/mute control, HTTP renderer casting).
   * mpv is fine for simple local playback.

---

## Data sources

* [Radio-Browser](https://www.radio-browser.info/) public API mirrors

---

## Thanks

Huge thanks to the Radio-Browser community for the servers and hosting of the API resources. Without BlazieTech first including a similar browser in their [BTSpeak product](https://www.blazietech.com/bt-speak-pro) and me wanting a lightweight experience on Linux that didn't load a bunch of on-page ads, this was born. Beyond essential feature sets, it shares very little in similarity to the one shipped by BlazieTech, thus the release. No code was borrowed; This was re-written from scratch to work strictly within a desktop or headless environment and not operated via a Braille keypad. 

---

## Example: environment presets

```bash
# force text prompts; use ALSA card 2, device 0; bigger volume steps
export RB_TEXT_MENU=1
export RB_AUDIO=alsa
export RB_ALSA_DEVICE=plughw:2,0
export RB_VLC_VOLSTEP=10
./radio.py
```
