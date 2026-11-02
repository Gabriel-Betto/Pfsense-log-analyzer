"""Leitura do filterlog do pfSense.

O pfSense grava cada decisão do firewall como uma linha de syslog cujo texto é um CSV:

    Nov  2 00:12:01 filterlog[4321]: 82,,,1000000103,em0,match,block,in,4,0x0,,52,41234,0,none,6,tcp,52,203.0.113.50,192.0.2.10,44123,22,0,S,1000,,1024,,mss

Campos (documentação oficial do Netgate, "Raw Filter Log Format"):
  comuns:  regra, sub-regra, âncora, tracker, interface, motivo, ação, direção, versão do IP
  IPv4:    TOS, ECN, TTL, ID, offset, flags, nº do protocolo, protocolo, tamanho, origem, destino
  IPv6:    classe, flow label, hop limit, protocolo, nº do protocolo, tamanho, origem, destino
  TCP:     porta origem, porta destino, tamanho dos dados, flags TCP, seq, ack, janela, urg, opções
  UDP:     porta origem, porta destino, tamanho dos dados

Aceita o formato BSD (sem ano) e o RFC 5424 (ISO 8601), em texto puro, gzip ou bzip2.
"""
from __future__ import annotations

import bz2
import gzip
import io
import ipaddress
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

MESES = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_BSD = re.compile(r"^(?:<\d+>)?(?P<mes>[A-Z][a-z]{2})\s+(?P<dia>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s")
_ISO = re.compile(r"^(?:<\d+>\d*\s*)?(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?(?P<tz>Z|[+-]\d{2}:?\d{2})?\s")
_GANCHO = re.compile(r"filterlog(?:\[\d+\])?:?\s+(?P<resto>.*)$")
_NOME = re.compile(r"^[A-Za-z0-9._:-]{1,32}$")
_ACAO = re.compile(r"^[a-z-]{2,12}$")


@dataclass(frozen=True, slots=True)
class Registro:
    quando: datetime
    regra: str
    tracker: str
    interface: str
    acao: str
    direcao: str
    versao: int
    proto: str
    origem: str
    destino: str
    porta_origem: int | None
    porta_destino: int | None
    flags: str


class Leitura:
    """Contadores de qualidade da leitura (para o relatório dizer quanto foi aproveitado)."""

    def __init__(self):
        self.linhas = 0      # linhas lidas
        self.validas = 0     # registros de filterlog aproveitados
        self.invalidas = 0   # tinham filterlog, mas o formato não bateu
        self.outras = 0      # linhas de outros serviços (ignoradas sem alarde)


def _inteiro(txt: str) -> int | None:
    return int(txt) if txt.isdigit() else None


def _ip(txt: str) -> str | None:
    try:
        return str(ipaddress.ip_address(txt.strip()))
    except ValueError:
        return None


def _porta(txt: str) -> int | None:
    n = _inteiro(txt)
    return n if n is not None and 0 <= n <= 65535 else None


def _csv_da_linha(linha: str) -> str | None:
    m = _GANCHO.search(linha)
    if not m:
        return None
    for token in m.group("resto").split():
        if "," in token:
            return token
    return None


class Relogio:
    """Resolve a data das linhas. O syslog BSD não traz o ano; vira o ano quando o mês volta de dezembro para janeiro."""

    def __init__(self, ano: int):
        self.ano = ano
        self._mes_anterior = 0

    def quando(self, linha: str) -> datetime | None:
        m = _ISO.match(linha)
        if m:
            texto = m.group("ts")
            frac = (m.group("frac") or "")[1:7].ljust(6, "0") if m.group("frac") else "000000"
            try:
                return datetime.fromisoformat(f"{texto}.{frac}")   # o fuso é descartado: vale o horário que o firewall mostra
            except ValueError:
                return None
        m = _BSD.match(linha)
        if not m or m.group("mes") not in MESES:
            return None
        mes = MESES[m.group("mes")]
        if self._mes_anterior and self._mes_anterior - mes > 6:
            self.ano += 1
        self._mes_anterior = mes
        try:
            return datetime(self.ano, mes, int(m.group("dia")), int(m.group("h")), int(m.group("m")), int(m.group("s")))
        except ValueError:
            return None


def interpretar(csv: str, quando: datetime) -> Registro | None:
    c = csv.split(",")
    if len(c) < 9:
        return None
    regra, _sub, _ancora, tracker, iface, _motivo, acao, direcao, versao = c[:9]
    if versao not in ("4", "6") or direcao not in ("in", "out") or not _ACAO.match(acao):
        return None
    if not (_NOME.match(iface) and _NOME.match(regra) and (not tracker or _NOME.match(tracker))):
        return None
    if versao == "4":
        if len(c) < 20:
            return None
        proto, origem, destino, resto = c[16].lower(), _ip(c[18]), _ip(c[19]), c[20:]
    else:
        if len(c) < 17:
            return None
        proto, origem, destino, resto = c[12].lower(), _ip(c[15]), _ip(c[16]), c[17:]
    if not origem or not destino or not re.fullmatch(r"[a-z0-9-]{1,16}", proto):
        return None
    p_orig = p_dest = None
    flags = ""
    if proto in ("tcp", "udp") and len(resto) >= 2:
        p_orig, p_dest = _porta(resto[0]), _porta(resto[1])
        if p_orig is None or p_dest is None:
            return None
        if proto == "tcp" and len(resto) >= 4 and re.fullmatch(r"[A-Za-z]{0,8}", resto[3]):
            flags = resto[3]
    return Registro(quando, regra, tracker, iface, acao, direcao, int(versao), proto, origem, destino, p_orig, p_dest, flags)


def ler_linhas(linhas: Iterable[str], ano: int, leitura: Leitura | None = None, relogio: Relogio | None = None) -> Iterator[Registro]:
    leitura = leitura if leitura is not None else Leitura()
    relogio = relogio or Relogio(ano)
    for linha in linhas:
        leitura.linhas += 1
        csv = _csv_da_linha(linha)
        if csv is None:
            leitura.outras += 1
            continue
        quando = relogio.quando(linha)
        registro = interpretar(csv, quando) if quando else None
        if registro is None:
            leitura.invalidas += 1
            continue
        leitura.validas += 1
        yield registro


def abrir_texto(caminho: str):
    """Abre texto puro, .gz ou .bz2 (detecta pelo conteúdo, não pela extensão). '-' lê da entrada padrão."""
    if caminho == "-":
        return sys.stdin
    with open(caminho, "rb") as f:
        inicio = f.read(3)
    if inicio[:2] == b"\x1f\x8b":
        bruto = gzip.open(caminho, "rb")
    elif inicio == b"BZh":
        bruto = bz2.open(caminho, "rb")
    else:
        bruto = open(caminho, "rb")
    return io.TextIOWrapper(bruto, encoding="utf-8", errors="replace", newline=None)


def ler_arquivos(caminhos: Iterable[str], ano: int, leitura: Leitura | None = None) -> Iterator[Registro]:
    leitura = leitura if leitura is not None else Leitura()
    relogio = Relogio(ano)   # um só para todos os arquivos: o ano continua certo se o log atravessar o Réveillon
    for caminho in caminhos:
        if caminho != "-" and not Path(caminho).is_file():
            raise FileNotFoundError(caminho)
        with abrir_texto(caminho) as f:
            yield from ler_linhas(f, ano, leitura, relogio)
