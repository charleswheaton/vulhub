#!/usr/bin/env python3
"""
Convert a Vulhub lab that uses images + bind mounts into buildable images with no host volumes.

Key features:
- Per-service Dockerfile at containers/<service>/Dockerfile (or one multi-stage Dockerfile with --single-dockerfile)
- Copies local bind-mount sources into the image via COPY directives
- ALWAYS rewrites ports to random host ports:
  * Compose v2 files -> short syntax "0:<container_port>"
  * Compose v3+/Spec -> long syntax {target: <container_port>, published: 0}
- Works with string or long-form 'volumes' and 'ports'
- Leaves multi-service labs intact (one Dockerfile per service)
- Prints a suggested catalog entry (JSON)
- Optional: append/merge that entry into a catalog JSON file (--append-catalog)

Usage examples in the docstring of previous replies.
"""

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

COMPOSE_BASENAMES = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
]

HTTP_INTERNAL_PORT_GUESS = [80, 8080, 3000, 5000]


# ---------------- helpers ----------------

def find_compose_file(lab_dir: Path) -> Optional[Path]:
    for name in COMPOSE_BASENAMES:
        p = lab_dir / name
        if p.exists():
            return p
    return None


def is_local_bind_volume(v) -> bool:
    """True if the volume is a host bind of a relative path like ./www:/dst or ./file:/dst"""
    if isinstance(v, str):
        parts = v.split(":")
        if len(parts) >= 2:
            src = parts[0].strip()
            if src.startswith("./") or (src and not src.startswith("/") and not src.endswith(":")):
                return True
    if isinstance(v, dict):
        t = v.get("type", "bind")
        src = v.get("source")
        if t == "bind" and isinstance(src, str) and (src.startswith("./") or (src and not src.startswith("/"))):
            return True
    return False


def parse_volume_src_dst(v) -> Optional[Tuple[str, str]]:
    if isinstance(v, str):
        parts = v.split(":")
        if len(parts) >= 2:
            return parts[0].strip(), parts[1].strip()
    elif isinstance(v, dict):
        if v.get("type", "bind") == "bind":
            src = v.get("source")
            dst = v.get("target")
            if src and dst:
                return src, dst
    return None


def normalize_copy_src(src: str) -> str:
    return src.replace("\\", "/")


def ensure_backup(path: Path):
    bak = path.with_suffix(path.suffix + ".bak")
    if not bak.exists():
        shutil.copy2(path, bak)


def make_service_dockerfile_text(base_image: str, copies: List[Tuple[str, str]]) -> str:
    lines = [f"FROM {base_image}"]
    for src, dst in copies:
        lines.append(f"COPY {normalize_copy_src(src)} {dst}")
    lines.append("")  # trailing newline
    return "\n".join(lines)


def parse_ports_to_structured(ports) -> List[Dict[str, Any]]:
    """
    Parse ports into a structured list of dicts: [{"target": <container_port>, "protocol": "tcp|udp"}]
    (We don't keep host because we will randomize it.)
    """
    out = []
    if not ports:
        return out
    for p in ports:
        if isinstance(p, str):
            proto = "tcp"
            s = p.strip()
            if "/" in s:
                s, proto = s.split("/", 1)
            if ":" in s:
                _, cont = s.split(":", 1)
                try:
                    cont_port = int(cont)
                except Exception:
                    continue
            else:
                try:
                    cont_port = int(s)
                except Exception:
                    continue
            out.append({"target": cont_port, "protocol": proto})
        elif isinstance(p, dict):
            # long syntax variants
            if "target" in p:
                out.append({"target": int(p["target"]), "protocol": p.get("protocol", "tcp")})
            elif "container_port" in p:
                out.append({"target": int(p["container_port"]), "protocol": p.get("protocol", "tcp")})
    return out


def to_ports_random_for_compose_version(compose_version: Optional[str], structured: List[Dict[str, Any]]):
    """
    For Compose v2, return short strings like "0:80" (or "0:53/udp").
    For newer specs / unspecified, return long syntax with published: 0.
    """
    v = (compose_version or "").strip().strip("'\"")
    if v.startswith("2"):
        out = []
        for item in structured:
            t = item["target"]
            proto = item.get("protocol", "tcp")
            s = f"0:{t}"
            if proto != "tcp":
                s = f"{s}/{proto}"
            out.append(s)
        return out
    else:
        # long syntax
        return [{"target": item["target"], "published": 0, "protocol": item.get("protocol", "tcp")} for item in structured]


def guess_primary_service(services: Dict[str, Any]) -> str:
    preferred_names = ["nginx", "web", "app", "frontend"]
    for name in preferred_names:
        if name in services:
            return name
    for name, svc in services.items():
        ports = svc.get("ports") or []
        structured = parse_ports_to_structured(ports)
        for it in structured:
            if it.get("target") in HTTP_INTERNAL_PORT_GUESS:
                return name
    return next(iter(services.keys()))


def relpath_from(root: Path, p: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except Exception:
        return p.as_posix()


# ---------------- core transform ----------------

def transform_lab(lab_dir: Path, single_dockerfile: bool = False, force: bool = False) -> Dict[str, Any]:
    compose_path = find_compose_file(lab_dir)
    if not compose_path:
        raise FileNotFoundError(f"No docker-compose.* found in {lab_dir}")

    with compose_path.open("r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    if not isinstance(compose, dict) or "services" not in compose:
        raise ValueError(f"{compose_path} has no 'services:'")

    compose_version = compose.get("version")
    services = compose["services"]
    containers_dir = lab_dir / "containers"
    containers_dir.mkdir(exist_ok=True)

    suggested_primary_http_ports: List[int] = []
    service_reports = []
    single_df_lines: List[str] = []

    for svc_name, svc in services.items():
        base_image = svc.get("image")
        did_write_df = False
        copies: List[Tuple[str, str]] = []

        if base_image:
            # Prepare COPYs from local bind mounts only when we control the base image
            volumes = svc.get("volumes") or []
            local_binds = [v for v in volumes if is_local_bind_volume(v)]
            for v in local_binds:
                parsed = parse_volume_src_dst(v)
                if not parsed:
                    continue
                src, dst = parsed
                src_path = (lab_dir / src).resolve()
                if not src_path.exists():
                    print(f"[WARN] {svc_name}: local volume source not found: {src}", file=sys.stderr)
                    continue
                copies.append((relpath_from(lab_dir, src_path), dst))

            # Generate Dockerfile(s)
            if single_dockerfile:
                target = svc_name.replace("-", "_")
                single_df_lines.append(f"# --- stage: {target} ---")
                single_df_lines.append(f"FROM {base_image} AS {target}")
                for src, dst in copies:
                    single_df_lines.append(f"COPY {normalize_copy_src(src)} {dst}")
                single_df_lines.append("")  # spacer
                dockerfile_rel = "Dockerfile"
            else:
                svc_dir = containers_dir / svc_name
                svc_dir.mkdir(parents=True, exist_ok=True)
                dockerfile_path = svc_dir / "Dockerfile"
                dockerfile_rel = relpath_from(lab_dir, dockerfile_path)
                if dockerfile_path.exists() and not force:
                    print(f"[SKIP] {dockerfile_rel} exists (use --force to overwrite)")
                else:
                    text = make_service_dockerfile_text(base_image, copies)
                    dockerfile_path.write_text(text, encoding="utf-8")
                    print(f"[WRITE] {dockerfile_rel}")
                    did_write_df = True

            # Rewrite service in compose:
            svc.pop("image", None)
            svc.pop("volumes", None)
            build_dict = {"context": ".", "dockerfile": dockerfile_rel}
            if single_dockerfile:
                build_dict["target"] = svc_name.replace("-", "_")
            svc["build"] = build_dict

        # ALWAYS randomize ports, even for build-based services
        structured = parse_ports_to_structured(svc.get("ports") or [])
        if structured:
            svc["ports"] = to_ports_random_for_compose_version(compose_version, structured)
            suggested_primary_http_ports.extend(it["target"] for it in structured if isinstance(it.get("target"), int))

        # Record report
        service_reports.append({
            "service": svc_name,
            "dockerfile": (
                ("Dockerfile (target: " + svc_name.replace("-", "_") + ")") if (base_image and single_dockerfile)
                else (f"containers/{svc_name}/Dockerfile" if base_image else "(existing build)")
            ),
            "copied": copies,
            "dockerfile_written": did_write_df or (base_image and single_dockerfile),
        })

    # If we used a single Dockerfile, write it now (if needed)
    if single_dockerfile and single_df_lines:
        dockerfile_path = lab_dir / "Dockerfile"
        if dockerfile_path.exists() and not force:
            print(f"[SKIP] Dockerfile exists (use --force to overwrite)")
        else:
            dockerfile_path.write_text("\n".join(single_df_lines) + "\n", encoding="utf-8")
            print(f"[WRITE] Dockerfile")

    # Backup compose then write
    ensure_backup(compose_path)
    with compose_path.open("w", encoding="utf-8") as f:
        yaml.dump(compose, f, sort_keys=False)

    # Suggest catalog entry
    primary = guess_primary_service(compose["services"])
    primary_http = sorted(set([p for p in suggested_primary_http_ports if isinstance(p, int)])) or HTTP_INTERNAL_PORT_GUESS

    compose_dir_in_container = f"/data/vulhub/{relpath_from(Path.cwd(), lab_dir)}"
    catalog_entry = {
        "provider": "vulhub",
        "compose_dir": compose_dir_in_container,
        "primary_service": primary,
        "primary_http_ports": primary_http,
        "health": {"path": "/", "expect_status": [200, 302, 401, 403]},
    }

    return {
        "lab_dir": str(lab_dir),
        "compose_path": str(compose_path),
        "services": service_reports,
        "primary_service": primary,
        "catalog_entry": catalog_entry,
    }


# ---------------- catalog append helpers ----------------

_backed_up_catalogs: set = set()

def _read_json_object(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Catalog at {path} must be a JSON object at the top level.")
    return data

def _backup_once(path: Path):
    if path in _backed_up_catalogs or not path.exists():
        return
    bak = path.with_suffix(path.suffix + ".bak")
    if not bak.exists():
        shutil.copy2(path, bak)
    _backed_up_catalogs.add(path)

def _write_json_object(path: Path, obj: Dict[str, Any]):
    tmp = path.with_suffix(path.suffix + f".tmp{int(time.time()*1000)}")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
    tmp.replace(path)

def append_to_catalog(catalog_path: Path, key: str, entry: Dict[str, Any], no_overwrite: bool = False):
    catalog = _read_json_object(catalog_path)
    if key in catalog and no_overwrite:
        print(f"[SKIP] catalog key exists and --no-overwrite set: {key}")
        return
    catalog[key] = entry
    _backup_once(catalog_path)
    _write_json_object(catalog_path, catalog)
    print(f"[UPDATE] appended catalog entry '{key}' → {catalog_path}")


# ---------------- CLI ----------------

def transform_all(root: Path, **kwargs) -> List[Dict[str, Any]]:
    results = []
    for p in root.rglob("docker-compose.yml"):
        results.append(transform_lab(p.parent, **kwargs))
    for p in root.rglob("docker-compose.yaml"):
        results.append(transform_lab(p.parent, **kwargs))
    return results

def main():
    ap = argparse.ArgumentParser(description="Convert Vulhub labs to build-based images (no bind mounts).")
    ap.add_argument("path", help="Path to a single lab directory OR Vulhub root when using --all")
    ap.add_argument("--all", action="store_true", help="Process all labs under the given root")
    ap.add_argument("--force", action="store_true", help="Overwrite existing Dockerfiles / Dockerfile")
    ap.add_argument("--single-dockerfile", action="store_true", help="Use one multi-stage Dockerfile with targets per service")
    ap.add_argument("--append-catalog", help="Path to a catalog.json to append/merge entries into")
    ap.add_argument("--catalog-key", help="Key name to use for the catalog entry (single-lab mode only). Defaults to the lab directory name.")
    ap.add_argument("--no-overwrite", action="store_true", help="Do not overwrite existing keys in the catalog JSON")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Not found: {root}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.all:
            results = transform_all(root, single_dockerfile=args.single_dockerfile, force=args.force)
            for r in results:
                print("\n=== Transformed:", r["lab_dir"], "===")
                for s in r["services"]:
                    print(f"- {s['service']}: Dockerfile -> {s['dockerfile']}")
                    for src, dst in s["copied"]:
                        print(f"  COPY {src} -> {dst}")
                lab_key = Path(r["lab_dir"]).name
                print("\nSuggested catalog entry (JSON):")
                print(json.dumps({lab_key: r["catalog_entry"]}, indent=2))
                if args.append_catalog:
                    append_to_catalog(Path(args.append_catalog), lab_key, r["catalog_entry"], no_overwrite=args.no_overwrite)
        else:
            r = transform_lab(root, single_dockerfile=args.single_dockerfile, force=args.force)
            print("\nServices converted:")
            for s in r["services"]:
                print(f"- {s['service']}: Dockerfile -> {s['dockerfile']}")
                for src, dst in s["copied"]:
                    print(f"  COPY {src} -> {dst}")
            lab_key = args.catalog_key or Path(r["lab_dir"]).name
            print("\nSuggested catalog entry (JSON):")
            print(json.dumps({lab_key: r["catalog_entry"]}, indent=2))
            if args.append_catalog:
                append_to_catalog(Path(args.append_catalog), lab_key, r["catalog_entry"], no_overwrite=args.no_overwrite)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
