"""``tracer`` — the TRACER Sync command-line interface.

Commands:
  entity create    Create a named entity (org/team) with an entity password + first admin.
  entity add-user  Add a user or admin under the entity (admins only).
  login            Authenticate: entity name + entity password + username + password.
  logout           Drop the local session (and revoke the server token).
  keys setup       Generate (or reuse) an SSH ed25519 keypair and register the public key.
  keys list        Show every public key registered under the entity.
  push             Encrypt the trace data locally and upload the blob (versioned).
  pull             Download the latest (or a given) version and decrypt it locally.
  review           Changes awaiting review; accept/reject one (admins only).
  status           Entity, members, versions, local session at a glance.
  config           Show or set local sync configuration.

Design notes: argparse (consistent with ``codegraph-trace``), rich for
presentation. Passwords are prompted interactively (never echoed, never
stored locally); non-interactive use can pass ``--password``-style flags.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import review
from .client import SyncClient
from .crypto import CryptoError
from .payload import PayloadError
from .sshkeys import (
    KeyError_,
    default_key_path,
    find_existing_ssh_keys,
    generate_keypair,
    is_passphrase_protected,
    load_keypair,
    resolve_keypair,
)
from .state import LocalState, NotLoggedIn, SyncConfig
from .transport import ApiError, HttpTransport, TransportError

console = Console()
err_console = Console(stderr=True, style="bold red")

COMPAT_NOTICE = "TRACER is currently [bold]OpenHands compatible only[/bold]."


def _notice() -> None:
    console.print(f"[dim]◦ {COMPAT_NOTICE}[/dim]")


def _client(state: LocalState) -> SyncClient:
    cfg = state.load_config()
    return SyncClient(state, HttpTransport(cfg.api_base_url))


def _prompt_secret(label: str, provided: Optional[str], confirm: bool = False) -> str:
    if provided:
        return provided
    while True:
        value = getpass.getpass(f"{label}: ")
        if not value:
            console.print("[yellow]Value cannot be empty.[/yellow]")
            continue
        if not confirm:
            return value
        again = getpass.getpass(f"{label} (again): ")
        if value == again:
            return value
        console.print("[yellow]Entries did not match — try again.[/yellow]")


def _prompt(label: str, provided: Optional[str]) -> str:
    if provided:
        return provided
    while True:
        value = input(f"{label}: ").strip()
        if value:
            return value
        console.print("[yellow]Value cannot be empty.[/yellow]")


# ---------------------------------------------------------------------------
# per-repo sync bookkeeping (last seen version, for conflict detection)
# ---------------------------------------------------------------------------

def _repos_path(state: LocalState) -> Path:
    return state.home / "repos.json"


def _get_last_version(state: LocalState, repo: Path) -> Optional[int]:
    path = _repos_path(state)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
        return data.get(str(Path(repo).resolve()), {}).get("last_version")
    except (json.JSONDecodeError, OSError):
        return None


def _set_last_version(state: LocalState, repo: Path, version: int) -> None:
    path = _repos_path(state)
    data = {}
    if path.is_file():
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            data = {}
    data[str(Path(repo).resolve())] = {"last_version": version}
    state.ensure_home()
    path.write_text(json.dumps(data, indent=2) + "\n")


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_entity_create(args: argparse.Namespace, state: LocalState) -> int:
    console.print(
        Panel.fit(
            "Create a new [bold]entity[/bold] — a named team/organization whose members\n"
            "share TRACER dev data end-to-end encrypted. You will become its first admin.",
            title="tracer entity create",
            border_style="cyan",
        )
    )
    entity = _prompt("Entity name (e.g. EpsilonAI)", args.entity)
    entity_password = _prompt_secret("Entity password", args.entity_password, confirm=True)
    admin = _prompt("Your admin username", args.admin)
    admin_password = _prompt_secret("Your admin password", args.admin_password, confirm=True)

    client = _client(state)
    client.entity_create(entity, entity_password, admin, admin_password)
    console.print(f"\n[green]✓[/green] Entity [bold]{entity}[/bold] created with admin [bold]{admin}[/bold].")
    console.print(
        "[dim]Next:[/dim] tracer login  →  tracer keys setup  →  tracer push"
    )
    return 0


def cmd_entity_add_user(args: argparse.Namespace, state: LocalState) -> int:
    role = args.role
    username = _prompt("New member's username", args.username)
    password = _prompt_secret(f"Password for {username}", args.password, confirm=True)
    client = _client(state)
    client.add_user(username, password, role)
    console.print(f"[green]✓[/green] {role.capitalize()} [bold]{username}[/bold] added to the entity.")
    console.print(
        f"[dim]They can now log in with the entity name + entity password and "
        f"their own credentials, then run `tracer keys setup`.[/dim]"
    )
    return 0


def cmd_login(args: argparse.Namespace, state: LocalState) -> int:
    entity = _prompt("Entity name", args.entity)
    entity_password = _prompt_secret("Entity password", args.entity_password)
    username = _prompt("Username", args.username)
    password = _prompt_secret("Password", args.password)
    client = _client(state)
    session = client.login(entity, entity_password, username, password)
    console.print(
        f"[green]✓[/green] Logged in to [bold]{entity}[/bold] as "
        f"[bold]{username}[/bold] ({session.role}). Session valid until {session.expires_at}."
    )
    try:
        resolve_keypair(state.home, client.config.ssh_key)
    except KeyError_:
        console.print(
            "[yellow]! No SSH key set up yet — run [bold]tracer keys setup[/bold] "
            "so pushes can encrypt to you and you can decrypt pulls.[/yellow]"
        )
    return 0


def cmd_logout(args: argparse.Namespace, state: LocalState) -> int:
    client = _client(state)
    client.logout()
    console.print("[green]✓[/green] Logged out.")
    return 0


def cmd_keys_setup(args: argparse.Namespace, state: LocalState) -> int:
    cfg = state.load_config()
    client = _client(state)

    if args.use_existing:
        priv = Path(args.use_existing).expanduser()
        if is_passphrase_protected(priv):
            err_console.print(
                f"✗ {priv} is passphrase-protected; TRACER needs an unencrypted key.\n"
                "  Re-run without --use-existing to generate a dedicated key."
            )
            return 2
        pair = load_keypair(priv)
        cfg.ssh_key = str(priv)
        state.save_config(cfg)
        console.print(f"[green]✓[/green] Reusing existing SSH key [bold]{priv}[/bold].")
    else:
        default = default_key_path(state.home)
        if default.is_file():
            pair = load_keypair(default)
            console.print(f"[green]✓[/green] Found existing TRACER key at [bold]{default}[/bold].")
        else:
            existing = find_existing_ssh_keys()
            if existing:
                console.print(
                    f"[dim]Found reusable key(s) in ~/.ssh: "
                    f"{', '.join(str(p) for p in existing)} — pass --use-existing <path> "
                    f"to use one of them. Generating a dedicated key instead.[/dim]"
                )
            pair = generate_keypair(default)
            console.print(f"[green]✓[/green] Generated new ed25519 keypair at [bold]{default}[/bold].")
        cfg.ssh_key = None  # default location
        state.save_config(cfg)

    fingerprint = client.register_key(pair)
    console.print(f"[green]✓[/green] Public key registered with the entity ({fingerprint}).")
    console.print(
        "[dim]Your private key never leaves this machine. Anyone pushing after now "
        "will encrypt to your key; ask a teammate to `tracer push` to grant you "
        "access to the current data.[/dim]"
    )
    return 0


def cmd_keys_list(args: argparse.Namespace, state: LocalState) -> int:
    client = _client(state)
    keys = client.list_keys()
    if not keys:
        console.print("[yellow]No public keys registered yet.[/yellow]")
        return 0
    table = Table(title="Registered SSH public keys", border_style="dim")
    table.add_column("User", style="bold")
    table.add_column("Fingerprint")
    table.add_column("Type")
    for k in keys:
        ktype = k["publicKey"].split()[0] if k.get("publicKey") else "?"
        table.add_row(k.get("username", "?"), k.get("fingerprint", "?"), ktype)
    console.print(table)
    return 0


def _print_diff(diff: str) -> None:
    """The before/after code for one reviewable change, git-diff style."""
    for line in diff.splitlines():
        if line.startswith(("diff --git", "index ", "+++", "---", "new file", "deleted file")):
            style = "bold dim"
        elif line.startswith("@@"):
            style = "cyan"
        elif line.startswith("+"):
            style = "green"
        elif line.startswith("-"):
            style = "red"
        else:
            style = ""
        console.print(Text("  " + line, style=style))


def cmd_push(args: argparse.Namespace, state: LocalState) -> int:
    session = state.require_session()
    client = _client(state)
    repo = Path(args.repo).resolve()
    base_version = _get_last_version(state, repo)

    # Verdicts a reviewer recorded since our last sync travel back in the encrypted
    # payload; pick them up so the author sees a rejection when they next push.
    review.sync_from_remote(client, repo, since_version=base_version)
    ledger = review.load(repo)
    ledger_before = ledger.to_dict()
    # Author side of a review: a rejected change shows its before/after code, nothing else.
    # Printed before the upload so a version conflict cannot swallow it.
    for unit in ledger.rejected_for(session.username):
        _print_diff(unit.diff)
        console.print()
    # Pushing is the author's answer to a rejection, so the units close in the payload
    # we are about to upload — the reviewer sees them closed too.
    review.supersede_rejected(ledger, session.username, by=session.username)
    # Every step recorded here since the team last saw this repo becomes reviewable.
    review.record_local(
        repo, ledger, author=session.username, push_message=args.message or ""
    )
    review.save(repo, ledger)

    try:
        with console.status("[cyan]Packing, encrypting and uploading…[/cyan]"):
            result = client.push(
                repo,
                message=args.message or "",
                base_version=base_version,
                force=args.force,
            )
    except Exception:
        # The upload failed: nothing was shared, so the ledger must not claim it was.
        review.write_ledger(
            review.ledger_path(repo), review.ReviewLedger.from_dict(ledger_before)
        )
        raise
    _set_last_version(state, repo, result.version)
    console.print(
        f"[green]✓[/green] Pushed [bold]version {result.version}[/bold] "
        f"({result.size:,} bytes encrypted, sha256 {result.sha256[:12]}…)."
    )
    console.print(
        f"[dim]Readable by: {', '.join(result.recipients)} — and no one else, "
        f"including the server.[/dim]"
    )
    return 0


def cmd_pull(args: argparse.Namespace, state: LocalState) -> int:
    session = state.require_session()
    client = _client(state)
    repo = Path(args.repo).resolve()
    # Verdicts recorded here before the pull; the archive replaces the synced tree.
    mine = review.load(repo)
    with console.status("[cyan]Downloading and decrypting…[/cyan]"):
        result = client.pull(repo, version=args.version)
    _set_last_version(state, repo, result.version)

    ledger = review.load(repo)
    ledger.merge(mine)
    review.save(repo, ledger)

    console.print(
        f"[green]✓[/green] Pulled [bold]version {result.version}[/bold] "
        f"(pushed by {result.pushed_by} at {result.created_at})."
    )
    console.print(f"  [dim]restored:[/dim] {', '.join(result.restored_paths)}")
    # Reviewer side: the commit message of each change awaiting review. The other three
    # surfaces (code structure, decision tree, before/after diff) live in the panel.
    for unit in ledger.pending_for(session.username):
        console.print(f"  {unit.commit_message}")
    # Author side: a rejected change shows its before/after code, nothing else.
    for unit in ledger.rejected_for(session.username):
        console.print()
        _print_diff(unit.diff)
    return 0


def cmd_review(args: argparse.Namespace, state: LocalState) -> int:
    """List changes awaiting review, or record a verdict (admins only)."""
    session = state.require_session()
    repo = Path(args.repo).resolve()
    path = review.ledger_path(repo)
    if args.verdict:
        if session.role != "admin":
            err_console.print("✗ only an entity admin can accept or reject a change")
            return 7
        verdict = review.ACCEPTED if args.verdict == "accept" else review.REJECTED
        try:
            unit = review.decide(path, args.unit or "", verdict, by=session.username)
        except review.ReviewError as exc:
            err_console.print(f"✗ {exc}")
            return 2
        console.print(f"[green]✓[/green] {unit.unit_id} {unit.status}.")
        return 0
    ledger = review.read_ledger(path)
    for unit in ledger.pending_for(session.username):
        console.print(f"  [bold]{unit.unit_id}[/bold]  {unit.commit_message}")
    for unit in ledger.rejected_for(session.username):
        console.print()
        _print_diff(unit.diff)
    return 0


def cmd_status(args: argparse.Namespace, state: LocalState) -> int:
    session = state.load_session()
    if session is None:
        console.print("[yellow]Not logged in.[/yellow] Run [bold]tracer login[/bold].")
        return 0
    client = _client(state)
    info = client.status()
    console.print(
        Panel.fit(
            f"Entity   [bold]{info.get('entity')}[/bold]\n"
            f"You      [bold]{session.username}[/bold] ({info.get('role', session.role)})\n"
            f"Latest   version {info.get('latestVersion') or '— (nothing pushed yet)'}",
            title="tracer status",
            border_style="cyan",
        )
    )
    members = info.get("members", [])
    if members:
        table = Table(title="Members", border_style="dim")
        table.add_column("User", style="bold")
        table.add_column("Role")
        table.add_column("Keys")
        for m in members:
            table.add_row(m.get("username", "?"), m.get("role", "?"), str(m.get("keyCount", 0)))
        console.print(table)
    versions = info.get("versions", [])
    if versions:
        table = Table(title="Versions (encrypted at rest)", border_style="dim")
        table.add_column("#", justify="right")
        table.add_column("Pushed by")
        table.add_column("At")
        table.add_column("Size", justify="right")
        table.add_column("Message")
        for v in versions[-10:]:
            table.add_row(
                str(v.get("version")),
                v.get("pushedBy", "?"),
                v.get("createdAt", "?"),
                f"{v.get('size', 0):,} B",
                v.get("message", ""),
            )
        console.print(table)
    return 0


def cmd_config(args: argparse.Namespace, state: LocalState) -> int:
    cfg = state.load_config()
    if args.set:
        key, _, value = args.set.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "api_base_url":
            cfg.api_base_url = value
        elif key == "project_id":
            cfg.project_id = value
        elif key == "ssh_key":
            cfg.ssh_key = value or None
        elif key == "sync_paths":
            cfg.sync_paths = [p.strip() for p in value.split(",") if p.strip()]
        else:
            err_console.print(f"✗ unknown config key: {key}")
            return 2
        state.save_config(cfg)
        console.print(f"[green]✓[/green] {key} updated.")
    console.print_json(json.dumps(cfg.to_dict()))
    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracer",
        description="TRACER Sync — zero-knowledge team sync for TRACER dev data.",
    )
    sub = parser.add_subparsers(dest="command")

    p_entity = sub.add_parser("entity", help="Manage the entity (team/organization)")
    entity_sub = p_entity.add_subparsers(dest="entity_command")

    p_create = entity_sub.add_parser("create", help="Create a new entity (you become admin)")
    p_create.add_argument("--entity", help="Entity name")
    p_create.add_argument("--entity-password", help="Entity password (prompted if omitted)")
    p_create.add_argument("--admin", help="Admin username")
    p_create.add_argument("--admin-password", help="Admin password (prompted if omitted)")
    p_create.set_defaults(func=cmd_entity_create)

    p_add = entity_sub.add_parser("add-user", help="Add a user/admin under the entity (admin only)")
    p_add.add_argument("--username", help="New member's username")
    p_add.add_argument("--password", help="New member's password (prompted if omitted)")
    p_add.add_argument("--role", choices=["user", "admin"], default="user")
    p_add.set_defaults(func=cmd_entity_add_user)

    p_login = sub.add_parser("login", help="Log in (entity + entity password + user + password)")
    p_login.add_argument("--entity")
    p_login.add_argument("--entity-password")
    p_login.add_argument("--username")
    p_login.add_argument("--password")
    p_login.set_defaults(func=cmd_login)

    p_logout = sub.add_parser("logout", help="Log out and drop the local session")
    p_logout.set_defaults(func=cmd_logout)

    p_keys = sub.add_parser("keys", help="SSH key management")
    keys_sub = p_keys.add_subparsers(dest="keys_command")
    p_setup = keys_sub.add_parser("setup", help="Generate/reuse a keypair and register the public key")
    p_setup.add_argument(
        "--use-existing",
        metavar="PATH",
        help="Reuse an existing unencrypted SSH private key (e.g. ~/.ssh/id_ed25519)",
    )
    p_setup.set_defaults(func=cmd_keys_setup)
    p_klist = keys_sub.add_parser("list", help="List registered public keys")
    p_klist.set_defaults(func=cmd_keys_list)

    p_push = sub.add_parser("push", help="Encrypt local trace data and upload a new version")
    p_push.add_argument("--repo", default=".", help="Repository root (default: .)")
    p_push.add_argument("-m", "--message", help="Short description of this push")
    p_push.add_argument(
        "--force", action="store_true", help="Push even if someone pushed since your last sync"
    )
    p_push.set_defaults(func=cmd_push)

    p_pull = sub.add_parser("pull", help="Download and decrypt the shared trace data")
    p_pull.add_argument("--repo", default=".", help="Repository root (default: .)")
    p_pull.add_argument("--version", type=int, help="Specific version (default: latest)")
    p_pull.set_defaults(func=cmd_pull)

    p_review = sub.add_parser("review", help="Changes awaiting review, or record a verdict")
    p_review.add_argument("--repo", default=".", help="Repository root (default: .)")
    p_review.add_argument(
        "verdict", nargs="?", choices=["accept", "reject"],
        help="Record a verdict on UNIT (admins only)",
    )
    p_review.add_argument("unit", nargs="?", help="The change id to accept or reject")
    p_review.set_defaults(func=cmd_review)

    p_status = sub.add_parser("status", help="Entity, members and version history")
    p_status.set_defaults(func=cmd_status)

    p_config = sub.add_parser("config", help="Show or set local sync configuration")
    p_config.add_argument(
        "--set",
        metavar="KEY=VALUE",
        help="api_base_url=…, project_id=…, ssh_key=…, sync_paths=a,b",
    )
    p_config.set_defaults(func=cmd_config)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _notice()
    if not getattr(args, "func", None):
        # `tracer`, `tracer entity`, `tracer keys` without a subcommand
        if getattr(args, "command", None) == "entity":
            parser.parse_args(["entity", "--help"])
        elif getattr(args, "command", None) == "keys":
            parser.parse_args(["keys", "--help"])
        else:
            parser.print_help()
        return 0

    state = LocalState()
    try:
        return args.func(args, state)
    except NotLoggedIn as exc:
        err_console.print(f"✗ {exc}")
        return 3
    except ApiError as exc:
        err_console.print(f"✗ [{exc.code}] {exc.message}")
        return 4
    except TransportError as exc:
        err_console.print(f"✗ {exc}")
        return 5
    except (CryptoError, PayloadError, KeyError_) as exc:
        err_console.print(f"✗ {exc}")
        return 6
    except KeyboardInterrupt:
        console.print("\n[dim]aborted[/dim]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
