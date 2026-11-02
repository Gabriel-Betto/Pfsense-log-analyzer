from __future__ import annotations

import argparse
import ipaddress
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .analise import Analisador, Parametros
from .leitor import Leitura, ler_arquivos
from .relatorio import escrever_csvs, para_html, para_json, resumo_texto


def _rede(txt: str):
    try:
        return ipaddress.ip_network(txt, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(f"IP ou rede inválida: {txt}") from None


def _positivo(txt: str) -> int:
    try:
        n = int(txt)
    except ValueError:
        n = 0
    if n < 1:
        raise argparse.ArgumentTypeError("use um número inteiro maior que zero")
    return n


class _Parser(argparse.ArgumentParser):
    """Erro de uso sai com código 1 (o 2 é reservado para 'achado de gravidade ALTA')."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: erro: {message}\n")


def montar_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="pfloganalyzer", description="Analisa o filterlog do pfSense: varreduras, tentativas repetidas e portas expostas.")
    p.add_argument("arquivos", nargs="+", help="filter.log (texto, .gz ou .bz2); vários arquivos em ordem do mais antigo ao mais novo; '-' lê da entrada padrão")
    p.add_argument("--ano", type=int, default=date.today().year, help="ano das linhas (o syslog BSD não traz ano); padrão: ano atual")
    p.add_argument("--wan", action="append", default=[], metavar="IFACE", help="interface WAN (ex.: em0); pode repetir. Liga a checagem de portas expostas")
    p.add_argument("--janela", type=_positivo, default=300, help="janela de análise em segundos (padrão 300)")
    p.add_argument("--limite-portas", type=_positivo, default=15, help="portas distintas na janela para acusar varredura de portas (padrão 15)")
    p.add_argument("--limite-hosts", type=_positivo, default=10, help="destinos distintos na janela para acusar varredura de hosts (padrão 10)")
    p.add_argument("--limite-tentativas", type=_positivo, default=20, help="conexões novas a um serviço sensível na janela (padrão 20)")
    p.add_argument("--ignorar", nargs="+", type=_rede, default=[], metavar="IP/REDE", help="origens que não geram achados (ex.: seu scanner de vulnerabilidades)")
    p.add_argument("--top", type=_positivo, default=10, help="tamanho dos rankings (padrão 10)")
    p.add_argument("--saida", metavar="PASTA", help="grava CSVs, resumo.json e (com --html) relatorio.html nesta pasta")
    p.add_argument("--html", action="store_true", help="gera relatorio.html em --saida")
    p.add_argument("--sep", default=";", help="separador dos CSVs (padrão ';', abre direto no Excel pt-BR)")
    p.add_argument("--falhar-se-alta", action="store_true", help="sai com código 2 se houver achado de gravidade ALTA (útil em rotina agendada)")
    p.add_argument("--versao", action="version", version=f"pfloganalyzer {__version__}")
    return p


def _saida_tolerante() -> None:
    """Caractere que o console não representa vira '?' em vez de derrubar o programa (não força UTF-8: respeita o console)."""
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass  # fluxo substituído (testes, redirecionamento) sem reconfigure


def main(argv: list[str] | None = None) -> int:
    _saida_tolerante()
    args = montar_parser().parse_args(argv)
    if args.html and not args.saida:
        print("erro: --html precisa de --saida PASTA", file=sys.stderr)
        return 1
    parametros = Parametros(janela=args.janela, limite_portas=args.limite_portas, limite_hosts=args.limite_hosts,
                            limite_tentativas=args.limite_tentativas, wan=frozenset(args.wan), ignorar=tuple(args.ignorar))
    leitura = Leitura()
    analisador = Analisador(parametros, args.top)
    try:
        for registro in ler_arquivos(args.arquivos, args.ano, leitura):
            analisador.registrar(registro)
    except FileNotFoundError as e:
        print(f"erro: arquivo não encontrado: {e}", file=sys.stderr)
        return 1
    except (OSError, EOFError) as e:
        print(f"erro ao ler o arquivo: {e}", file=sys.stderr)
        return 1
    res = analisador.resultado()
    if leitura.validas == 0:
        print("Nenhuma linha de filterlog reconhecida. Confira se o arquivo é o filter.log do pfSense (Status > System Logs > Firewall).", file=sys.stderr)
        return 1
    print(resumo_texto(res, leitura, args.top))
    if args.saida:
        pasta = Path(args.saida)
        escritos = escrever_csvs(res, args.saida, args.sep)
        (pasta / "resumo.json").write_text(para_json(res, leitura), encoding="utf-8")
        escritos.append("resumo.json")
        if args.html:
            (pasta / "relatorio.html").write_text(para_html(res, leitura), encoding="utf-8")
            escritos.append("relatorio.html")
        print(f"\nArquivos gravados em {pasta}: {', '.join(escritos)}")
    if args.falhar_se_alta and res.por_gravidade()["ALTA"]:
        return 2
    return 0
