"""Análise do filterlog em uma única passada (memória limitada, serve para logs grandes)."""
from __future__ import annotations

import ipaddress
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .leitor import Registro

SENSIVEIS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 1433: "SQL Server", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM (HTTPS)",
}
SERVICOS = {
    **SENSIVEIS, 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP (envio)", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1194: "OpenVPN", 3128: "Proxy", 8080: "HTTP alternativo", 8443: "HTTPS alternativo",
}
BLOQUEIO = {"block", "reject"}
GRAVIDADES = {"ALTA": 0, "MÉDIA": 1, "BAIXA": 2, "INFO": 3}
_LOCAIS = [ipaddress.ip_network(r) for r in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]
_MAX_EVENTOS_POR_ORIGEM = 4000
_MAX_PORTAS_GUARDADAS = 256


def eh_local(ip: str) -> bool:
    """Endereço de rede interna (RFC 1918, loopback, link-local, ULA). Faixas de documentação contam como públicas."""
    a = ipaddress.ip_address(ip)
    return any(a in rede for rede in _LOCAIS)


@dataclass
class Parametros:
    janela: int = 300              # segundos
    limite_portas: int = 15        # portas distintas bloqueadas na janela => varredura de portas
    limite_hosts: int = 10         # destinos distintos bloqueados na janela => varredura de hosts
    limite_tentativas: int = 20    # conexões novas a um serviço sensível na janela => tentativas repetidas
    wan: frozenset[str] = frozenset()
    ignorar: tuple = ()            # redes (ipaddress) cujas origens não geram achados


@dataclass
class Achado:
    tipo: str
    gravidade: str
    origem: str
    inicio: datetime
    fim: datetime
    valor: int
    detalhe: str
    exemplos: list[str] = field(default_factory=list)


class _Janela:
    __slots__ = ("eventos", "portas", "hosts")

    def __init__(self):
        self.eventos: deque = deque()
        self.portas: Counter = Counter()
        self.hosts: Counter = Counter()

    @staticmethod
    def _tirar(contador: Counter, chave):
        contador[chave] -= 1
        if contador[chave] <= 0:
            del contador[chave]

    def adicionar(self, t: datetime, destino: str, porta: int | None, janela: int):
        self.eventos.append((t, destino, porta))
        self.hosts[destino] += 1
        if porta is not None:
            self.portas[porta] += 1
        limite = timedelta(seconds=janela)
        while self.eventos and (t - self.eventos[0][0] > limite or len(self.eventos) > _MAX_EVENTOS_POR_ORIGEM):
            _, d, p = self.eventos.popleft()
            self._tirar(self.hosts, d)
            if p is not None:
                self._tirar(self.portas, p)


class _Tentativas:
    __slots__ = ("eventos", "passou")

    def __init__(self):
        self.eventos: deque = deque()
        self.passou = 0

    def adicionar(self, t: datetime, passou: bool, janela: int):
        self.eventos.append((t, passou))
        self.passou += passou
        limite = timedelta(seconds=janela)
        while self.eventos and (t - self.eventos[0][0] > limite or len(self.eventos) > _MAX_EVENTOS_POR_ORIGEM):
            self.passou -= self.eventos.popleft()[1]


@dataclass
class Resultado:
    total: int = 0
    primeiro: datetime | None = None
    ultimo: datetime | None = None
    acoes: Counter = field(default_factory=Counter)
    interfaces: Counter = field(default_factory=Counter)
    protocolos: Counter = field(default_factory=Counter)
    top_origens: list = field(default_factory=list)      # (ip, bloqueios, portas_distintas, escopo)
    top_portas: list = field(default_factory=list)       # (porta, protocolo, servico, bloqueios)
    regras: list = field(default_factory=list)           # (regra, tracker, acao, quantidade)
    por_hora: list = field(default_factory=list)         # (hora, bloqueios, liberados)
    portas_wan: list = field(default_factory=list)       # (porta, servico, liberados)
    achados: list = field(default_factory=list)

    @property
    def bloqueios(self) -> int:
        return sum(n for a, n in self.acoes.items() if a in BLOQUEIO)

    def por_gravidade(self) -> Counter:
        return Counter(a.gravidade for a in self.achados)


class Analisador:
    def __init__(self, parametros: Parametros | None = None, top: int = 10):
        self.p = parametros or Parametros()
        self.top = top
        self.r = Resultado()
        self._bloq_origem: Counter = Counter()
        self._portas_origem: dict[str, set] = {}
        self._bloq_porta: Counter = Counter()
        self._regras: Counter = Counter()
        self._horas: dict[datetime, list] = {}
        self._janelas: dict[str, _Janela] = {}
        self._tentativas: dict[tuple, _Tentativas] = {}
        self._varreduras: dict[tuple, Achado] = {}
        self._repetidas: dict[tuple, Achado] = {}
        self._expostas: dict[tuple, Achado] = {}
        self._origens_expostas: dict[tuple, set] = {}
        self._wan_liberadas: Counter = Counter()
        self._privados_wan: dict[str, Achado] = {}
        self._desde_limpeza = 0

    # --------------------------------------------------------------- entrada
    def _ignorado(self, ip: str) -> bool:
        if not self.p.ignorar:
            return False
        a = ipaddress.ip_address(ip)
        return any(a in rede for rede in self.p.ignorar)

    def _externo(self, reg: Registro) -> bool:
        if self.p.wan:
            return reg.interface in self.p.wan
        return not eh_local(reg.origem)

    def registrar(self, reg: Registro) -> None:
        r = self.r
        r.total += 1
        r.primeiro = reg.quando if r.primeiro is None or reg.quando < r.primeiro else r.primeiro
        r.ultimo = reg.quando if r.ultimo is None or reg.quando > r.ultimo else r.ultimo
        r.acoes[reg.acao] += 1
        r.interfaces[reg.interface] += 1
        r.protocolos[reg.proto] += 1
        self._regras[(reg.regra, reg.tracker, reg.acao)] += 1
        bloqueado = reg.acao in BLOQUEIO
        hora = reg.quando.replace(minute=0, second=0, microsecond=0)
        contagem = self._horas.setdefault(hora, [0, 0])
        if bloqueado:
            contagem[0] += 1
        elif reg.acao == "pass":
            contagem[1] += 1
        if reg.direcao != "in" or self._ignorado(reg.origem):
            return
        if bloqueado:
            self._bloqueio(reg)
        self._servico_sensivel(reg)
        if reg.acao == "pass" and reg.interface in self.p.wan:
            self._wan_pass(reg)
        if reg.interface in self.p.wan and eh_local(reg.origem) and bloqueado:
            self._ip_privado_na_wan(reg)
        self._desde_limpeza += 1
        if self._desde_limpeza >= 100_000:
            self._limpar(reg.quando)

    # ---------------------------------------------------------------- regras
    def _bloqueio(self, reg: Registro) -> None:
        self._bloq_origem[reg.origem] += 1
        if reg.porta_destino is not None:
            self._bloq_porta[(reg.porta_destino, reg.proto)] += 1
            portas = self._portas_origem.setdefault(reg.origem, set())
            if len(portas) < _MAX_PORTAS_GUARDADAS:
                portas.add(reg.porta_destino)
        janela = self._janelas.setdefault(reg.origem, _Janela())
        janela.adicionar(reg.quando, reg.destino, reg.porta_destino, self.p.janela)
        externo = self._externo(reg)
        if len(janela.portas) >= self.p.limite_portas:
            self._marcar_varredura("varredura_portas", reg, len(janela.portas), externo, self.p.limite_portas, sorted(janela.portas)[:12])
        if len(janela.hosts) >= self.p.limite_hosts:
            self._marcar_varredura("varredura_hosts", reg, len(janela.hosts), externo, self.p.limite_hosts, sorted(janela.hosts)[:8])

    def _marcar_varredura(self, tipo: str, reg: Registro, n: int, externo: bool, limite: int, exemplos: list) -> None:
        chave = (tipo, reg.origem)
        achado = self._varreduras.get(chave)
        gravidade = "ALTA" if not externo else ("MÉDIA" if n >= 3 * limite else "BAIXA")
        if achado is None:
            self._varreduras[chave] = Achado(tipo, gravidade, reg.origem, reg.quando, reg.quando, n, "", [str(e) for e in exemplos])
            return
        achado.fim = max(achado.fim, reg.quando)
        if n > achado.valor:
            achado.valor, achado.exemplos = n, [str(e) for e in exemplos]
        if GRAVIDADES[gravidade] < GRAVIDADES[achado.gravidade]:
            achado.gravidade = gravidade

    def _servico_sensivel(self, reg: Registro) -> None:
        if reg.proto != "tcp" or reg.flags != "S" or reg.porta_destino not in SENSIVEIS:
            return
        passou = reg.acao == "pass"
        if not passou and reg.acao not in BLOQUEIO:
            return
        chave = (reg.origem, reg.porta_destino)
        janela = self._tentativas.setdefault(chave, _Tentativas())
        janela.adicionar(reg.quando, passou, self.p.janela)
        n = len(janela.eventos)
        if n < self.p.limite_tentativas:
            return
        externo = self._externo(reg)
        gravidade = ("ALTA" if janela.passou else "BAIXA") if externo else "MÉDIA"
        achado = self._repetidas.get(chave)
        if achado is None:
            self._repetidas[chave] = Achado("tentativas_repetidas", gravidade, reg.origem, reg.quando, reg.quando, n, "", [str(reg.porta_destino)])
            achado = self._repetidas[chave]
        achado.fim = max(achado.fim, reg.quando)
        achado.valor = max(achado.valor, n)
        if GRAVIDADES[gravidade] < GRAVIDADES[achado.gravidade]:
            achado.gravidade = gravidade

    def _wan_pass(self, reg: Registro) -> None:
        if reg.porta_destino is None:
            return
        self._wan_liberadas[reg.porta_destino] += 1
        if reg.porta_destino not in SENSIVEIS or reg.proto not in ("tcp", "udp"):
            return
        chave = (reg.regra, reg.tracker, reg.porta_destino)
        achado = self._expostas.get(chave)
        if achado is None:
            achado = self._expostas[chave] = Achado("porta_exposta", "ALTA", reg.regra, reg.quando, reg.quando, 0, "", [])
            achado.exemplos = [str(reg.porta_destino), reg.tracker]
        achado.fim = max(achado.fim, reg.quando)
        achado.valor += 1
        origens = self._origens_expostas.setdefault(chave, set())
        if len(origens) < 50:
            origens.add(reg.origem)

    def _ip_privado_na_wan(self, reg: Registro) -> None:
        achado = self._privados_wan.get(reg.origem)
        if achado is None:
            self._privados_wan[reg.origem] = Achado("ip_privado_na_wan", "MÉDIA", reg.origem, reg.quando, reg.quando, 1, "", [reg.interface])
            return
        achado.fim = max(achado.fim, reg.quando)
        achado.valor += 1

    def _limpar(self, agora: datetime) -> None:
        """Descarta janelas de origens paradas há mais que a janela de análise (mantém a memória baixa)."""
        limite = timedelta(seconds=self.p.janela)
        self._janelas = {k: j for k, j in self._janelas.items() if j.eventos and agora - j.eventos[-1][0] <= limite}
        self._tentativas = {k: j for k, j in self._tentativas.items() if j.eventos and agora - j.eventos[-1][0] <= limite}
        self._desde_limpeza = 0

    # ---------------------------------------------------------------- saída
    def resultado(self) -> Resultado:
        r = self.r
        wan = bool(self.p.wan)
        r.top_origens = [(ip, n, len(self._portas_origem.get(ip, ())), "interna" if eh_local(ip) else "externa")
                         for ip, n in self._bloq_origem.most_common(self.top)]
        r.top_portas = [(porta, proto, SERVICOS.get(porta, ""), n) for (porta, proto), n in self._bloq_porta.most_common(self.top)]
        r.regras = [(regra, tracker, acao, n) for (regra, tracker, acao), n in self._regras.most_common(self.top)]
        r.por_hora = [(h, b, p) for h, (b, p) in sorted(self._horas.items())]
        r.portas_wan = [(p, SERVICOS.get(p, ""), n) for p, n in self._wan_liberadas.most_common(self.top)] if wan else []
        achados: list[Achado] = []
        for a in self._varreduras.values():
            minutos = max(1, round(self.p.janela / 60))
            if a.tipo == "varredura_portas":
                a.detalhe = f"{a.valor} portas diferentes bloqueadas em até {minutos} min (ex.: {', '.join(a.exemplos)})"
            else:
                a.detalhe = f"{a.valor} destinos diferentes bloqueados em até {minutos} min (ex.: {', '.join(a.exemplos)})"
            achados.append(a)
        for (origem, porta), a in self._repetidas.items():
            nome = SENSIVEIS.get(porta, str(porta))
            exposto = "serviço liberado no firewall" if a.gravidade == "ALTA" else "tentativas bloqueadas"
            a.detalhe = f"{a.valor} conexões novas a {nome} (porta {porta}) em até {max(1, round(self.p.janela / 60))} min; {exposto}"
            achados.append(a)
        for (regra, tracker, porta), a in self._expostas.items():
            nome = SENSIVEIS.get(porta, str(porta))
            n_orig = len(self._origens_expostas.get((regra, tracker, porta), ()))
            a.origem = f"regra {regra}"
            a.detalhe = f"{nome} (porta {porta}) liberado na WAN: {a.valor} conexões aceitas de {n_orig} origem(ns) (tracker {tracker or 'n/d'})"
            achados.append(a)
        for a in self._privados_wan.values():
            a.detalhe = f"IP privado chegando pela WAN ({a.exemplos[0]}), {a.valor} pacotes bloqueados: possível spoofing ou erro de configuração"
            achados.append(a)
        r.achados = sorted(achados, key=lambda a: (GRAVIDADES[a.gravidade], -a.valor, a.inicio))
        return r


def analisar(registros, parametros: Parametros | None = None, top: int = 10) -> Resultado:
    a = Analisador(parametros, top)
    for reg in registros:
        a.registrar(reg)
    return a.resultado()
