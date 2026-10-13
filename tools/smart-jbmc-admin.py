#!/usr/bin/env python3
"""CLI administrativo do SMART-JBMC — gestão de usuários e API keys.

Roda offline (não precisa do servidor de pé) e usa as mesmas funções do backend.

Exemplos:
  python tools/smart-jbmc-admin.py create-admin franklin
  python tools/smart-jbmc-admin.py add-user aluno1
  python tools/smart-jbmc-admin.py list
  python tools/smart-jbmc-admin.py rotate-key 2
  python tools/smart-jbmc-admin.py delete 3
  python tools/smart-jbmc-admin.py history --limit 50
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

# Garante que `smart_jbmc` seja importável.
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "backend"))

from smart_jbmc.auth import service  # noqa: E402
from smart_jbmc.auth.db import user_count  # noqa: E402


def _prompt_password(confirm: bool = True) -> str:
    pw = getpass.getpass("Senha: ")
    if confirm:
        pw2 = getpass.getpass("Confirme a senha: ")
        if pw != pw2:
            print("Senhas não conferem.", file=sys.stderr)
            sys.exit(1)
    if len(pw) < 4:
        print("Senha deve ter pelo menos 4 caracteres.", file=sys.stderr)
        sys.exit(1)
    return pw


def cmd_create_admin(args: argparse.Namespace) -> int:
    if user_count() > 0 and not args.force:
        print("Já existem usuários cadastrados; use 'add-user' ou --force.", file=sys.stderr)
        return 1
    pw = args.password or _prompt_password()
    try:
        u = service.create_user(args.login, pw, role="admin")
    except ValueError as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 1
    print(f"Admin criado: id={u['id']} login={u['login']}")
    return 0


def cmd_add_user(args: argparse.Namespace) -> int:
    pw = args.password or _prompt_password()
    try:
        u = service.create_user(args.login, pw, role=args.role)
    except ValueError as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 1
    print(f"Usuário criado: id={u['id']} login={u['login']} role={u['role']}")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    users = service.list_users()
    if not users:
        print("(nenhum usuário cadastrado)")
        return 0
    fmt = "{:>3}  {:<20}  {:<6}  {:<14}  {:<19}  {:<19}"
    print(fmt.format("id", "login", "role", "api_key_prefix", "created_at", "last_login"))
    for u in users:
        print(fmt.format(
            u["id"], u["login"], u["role"],
            u.get("api_key_prefix") or "-",
            (u.get("created_at") or "-")[:19],
            (u.get("last_login") or "-")[:19],
        ))
    return 0


def cmd_rotate_key(args: argparse.Namespace) -> int:
    try:
        key = service.issue_api_key(args.uid)
    except ValueError as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 1
    print("Nova API key (mostrada UMA ÚNICA VEZ — guarde-a agora):")
    print(key)
    return 0


def cmd_revoke_key(args: argparse.Namespace) -> int:
    service.revoke_api_key(args.uid)
    print("API key revogada.")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    if not service.delete_user(args.uid):
        print(f"Usuário {args.uid} não encontrado.", file=sys.stderr)
        return 1
    print(f"Usuário {args.uid} excluído.")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    rows = service.list_login_history(limit=args.limit, user_id=args.user_id)
    if not rows:
        print("(sem registros)")
        return 0
    fmt = "{:<19}  {:<18}  {:<8}  {:<3}  {:<15}  {}"
    print(fmt.format("at", "login", "method", "ok", "ip", "user_agent"))
    for r in rows:
        print(fmt.format(
            (r["at"] or "-")[:19],
            (r["login"] or "-")[:18],
            r["method"], "✓" if r["success"] else "✗",
            (r.get("ip") or "-")[:15],
            (r.get("user_agent") or "-")[:60],
        ))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SMART-JBMC admin CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("create-admin", help="cria o primeiro admin (ou novo, com --force)")
    s.add_argument("login")
    s.add_argument("--password", help="senha em linha (omitir = perguntar interativamente)")
    s.add_argument("--force", action="store_true", help="criar admin mesmo com usuários existentes")
    s.set_defaults(func=cmd_create_admin)

    s = sub.add_parser("add-user", help="cria um usuário comum")
    s.add_argument("login")
    s.add_argument("--password", help="senha em linha (omitir = perguntar interativamente)")
    s.add_argument("--role", choices=["user", "admin"], default="user")
    s.set_defaults(func=cmd_add_user)

    s = sub.add_parser("list", help="lista usuários")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("rotate-key", help="gera/rotaciona a API key do usuário")
    s.add_argument("uid", type=int)
    s.set_defaults(func=cmd_rotate_key)

    s = sub.add_parser("revoke-key", help="revoga a API key do usuário")
    s.add_argument("uid", type=int)
    s.set_defaults(func=cmd_revoke_key)

    s = sub.add_parser("delete", help="exclui um usuário")
    s.add_argument("uid", type=int)
    s.set_defaults(func=cmd_delete)

    s = sub.add_parser("history", help="exibe o histórico de logins")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--user-id", type=int)
    s.set_defaults(func=cmd_history)

    return p


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
