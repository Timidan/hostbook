"""Hosts tab backend. Reads and edits the hostbook's own data. The only route that touches a machine
is a check, which runs the same read-only scan as the schedule, on the owner's click."""

import importlib.util
import re
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter()
GUEST_KIND = {"vm": "VM", "ct": "LXC"}
_PKG = Path(__file__).resolve().parents[1]


def _hb():
    """The plugin's own functions, loaded once under a private name."""
    name = "hostbook_dashboard_core"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _PKG / "__init__.py", submodule_search_locations=[str(_PKG)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _ok(problem):
    if problem:
        raise HTTPException(status_code=400, detail=problem)


@router.get("/hosts")
def hosts():  # plain def: FastAPI runs these off the event loop
    hb = _hb()
    book, catalog, history = hb.load_hosts(), hb.load_catalog(), hb.load_history()
    # A Proxmox guest whose name matches a hostbook alias is that machine: "docker-media runs on pve".
    runs_on = {s["name"]: f"{node}, {GUEST_KIND[s['kind']]} {s.get('id', '')}".strip()
               for node, entry in catalog.items() for s in entry.get("services", []) if s["kind"] in GUEST_KIND}
    out = []
    for name in sorted(book):
        entry = catalog.get(name, {})
        out.append({
            "name": name, "policy": book[name].get("policy", "approve"), "runs_on": runs_on.get(name),
            "scanned_at": entry.get("scanned_at"), "error": entry.get("error"), "fix": entry.get("fix"),
            "warnings": [hb.services.WARNINGS.get(w, (w, ""))[0] for w in entry.get("warnings", [])],
            "facts": entry.get("facts", {}), "history": [p[1] for p in history.get(name, [])],
            "services": [{k: s.get(k) for k in ("name", "kind", "state", "detail", "image", "ports") if s.get(k)}
                         for s in entry.get("services", [])],
        })
    return {"hosts": out, "settings": hb.load_settings()}


@router.get("/details")
def details(host: str, kind: str, name: str):
    """Live read-only details for one service, on the owner's click."""
    return _hb().service_details(host, kind, name)


@router.get("/setup")
def setup():
    hb = _hb()
    book, catalog, people = hb.load_hosts(), hb.load_catalog(), hb.load_people()
    return {
        "machines": [{
            "alias": n, "target": hb.target(s) + (f":{s['port']}" if s.get("port") else ""), "key": s.get("key"),
            "jump": s.get("jump"), "rule": s.get("policy", "approve"), "scheduled": s.get("scheduled", True),
            "ok": bool(catalog.get(n, {}).get("scanned_at")) and not catalog.get(n, {}).get("error"),
            "status": hb.status_line(catalog.get(n)),
        } for n, s in sorted(book.items())],
        "settings": hb.load_settings(),
        "schedules": list(hb.SCHEDULES),
        "scan_script": hb.services.SCAN_SCRIPT,
        "people": [{"key": key, "platform": key.partition(":")[0], "id": key.partition(":")[2],
                    "name": p.get("name", key), "role": p.get("role", "view"), "hosts": p.get("hosts")}
                   for key, p in sorted((people or {}).items())],
        "recent": [{"key": key, "platform": key.partition(":")[0], "id": key.partition(":")[2], "seen": seen,
                    "listed": key in (people or {})} for key, seen in hb._json("recent.json", {}).items()],
    }


def _check(alias):
    hb = _hb()
    book = hb.load_hosts()
    hb.record_scans(hb.scan_direct([alias], book), book, hb.load_settings()["disk_alert"])


@router.post("/discover")
def discover():
    """Ask the hostbook's Proxmox nodes (read-only) for guests that could be added, with their addresses."""
    return _hb().discover()


@router.post("/discover/evidence")
def discover_evidence():
    """Read-only facts the setup page hands to the model when the owner asks for AI help."""
    return _hb().evidence()


@router.post("/machines")
def add_machine(body: dict):
    alias = (body.get("alias") or "").strip()
    _ok(_hb().add_host(alias, body.get("target") or "", body.get("key") or None, body.get("jump") or None,
                       body.get("rule") or "approve"))
    _check(alias)
    return setup()


@router.post("/machines/{alias}")
def edit_machine(alias: str, body: dict):
    _ok(_hb().set_host(alias, rule=body.get("rule"), scheduled=body.get("scheduled")))
    return setup()


@router.delete("/machines/{alias}")
def delete_machine(alias: str):
    _ok(_hb().remove_host(alias))
    return setup()


@router.post("/machines/{alias}/check")
def check_machine(alias: str):
    _ok(None if alias in _hb().load_hosts() else f"{alias} isn't in the hostbook.")
    _check(alias)
    return setup()


@router.post("/schedule")
def schedule(body: dict):
    hb = _hb()
    try:
        disk_alert = max(50, min(99, int(body.get("disk_alert", hb.load_settings()["disk_alert"]))))
    except (TypeError, ValueError):
        _ok("The disk alert needs a number between 50 and 99.")
    with hb.locked():
        hb.save_settings({**hb.load_settings(), "disk_alert": disk_alert})
    _ok(hb.set_schedule(body.get("every") or "off", body.get("deliver") or None))
    return setup()


@router.post("/people")
def add_person(body: dict):
    hb = _hb()
    platform, uid = str(body.get("platform") or "").strip(), str(body.get("id") or "").strip()
    role = body.get("role") or "view"
    _ok(None if re.fullmatch(r"[a-z_]{2,24}", platform) else "Pick the chat platform this person uses.")
    _ok(None if uid and len(uid) <= 128 and not re.search(r"\s", uid) else "Enter their user id on that platform.")
    _ok(None if role in ("view", "operate", "owner") else "Access must be view, operate or owner.")
    pid = f"{platform}:{uid}"
    hosts = [h.strip() for h in (body.get("hosts") or "").split(",") if h.strip()]
    _ok(None if all(h in hb.load_hosts() for h in hosts) else "Only list machines that are in the hostbook.")
    with hb.locked():
        people = hb.load_people() or {}
        people[pid] = {"name": (body.get("name") or pid).strip(), "role": role, **({"hosts": hosts} if hosts else {})}
        hb.save_people(people)
    return setup()


@router.delete("/people/{pid}")
def delete_person(pid: str):
    hb = _hb()
    with hb.locked():
        people = hb.load_people() or {}
        people.pop(pid, None)
        hb.save_people(people)
    return setup()
