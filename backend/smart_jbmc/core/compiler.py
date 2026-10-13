"""Compilação Java/Kotlin para bytecode JVM (usa resolve_tool da config)."""

from pathlib import Path

from .config import resolve_tool
from .constants import JAVAC_RELEASE, KOTLIN_JVM_TARGET
from .process import ToolResult, run_cmd


class ToolNotFound(RuntimeError):
    """Ferramenta externa não encontrada (.env / tools/ / PATH)."""


def _require(tool: str) -> str:
    path = resolve_tool(tool)
    if not path:
        raise ToolNotFound(
            f"{tool} não encontrado. Configure {tool.upper()}_PATH no .env, "
            f"coloque o binário em tools/{tool}, ou instale-o no PATH."
        )
    return path


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def compile_java(files: list[str], out_dir: str, classpath: str | None = None) -> ToolResult:
    """Compila .java para `out_dir` (Java 8 para compatibilidade ampla da JVM).
    `classpath` (opcional) resolve dependências externas (ex.: stubs SV-COMP/CProver)."""
    ensure_dir(out_dir)
    cmd = [_require("javac"), "-g", "--release", JAVAC_RELEASE, "-d", out_dir]
    if classpath:
        cmd += ["-cp", classpath]
    cmd += list(files)
    return run_cmd(cmd)


def compile_java_patched(files: list[str], out_dir: str, patch_src: str,
                         classpath: str | None = None) -> ToolResult:
    """Compila classes que vivem em pacotes do JDK (`java.*`), para os modelos
    de biblioteca do JBMC.

    Sem `--patch-module java.base`, o javac recusa: "prohibited package name".
    E sem `--add-reads java.base=ALL-UNNAMED` o modelo não enxerga
    `org.cprover.CProver`, que está no classpath: código dentro de um módulo não
    lê o módulo sem nome.

    Aqui **não** se usa `--release`: ele é incompatível com `--patch-module`, e
    o bytecode destes modelos só precisa ser legível pelo JBMC — não é linkado
    com o código do usuário."""
    ensure_dir(out_dir)
    cmd = [_require("javac"), "-g", "--patch-module", f"java.base={patch_src}",
           "--add-reads", "java.base=ALL-UNNAMED", "-d", out_dir]
    if classpath:
        cmd += ["-cp", classpath]
    cmd += list(files)
    return run_cmd(cmd)


def compile_kotlin(files: list[str], out_dir: str, classpath: str | None = None) -> ToolResult:
    """Compila .kt para `out_dir`."""
    ensure_dir(out_dir)
    cmd = [_require("kotlinc"), "-jvm-target", KOTLIN_JVM_TARGET]
    if classpath:
        cmd += ["-classpath", classpath]
    cmd += [*files, "-d", out_dir]
    return run_cmd(cmd)
