"""Gera data/filter_exemplo.log: um filterlog FICTÍCIO no formato do pfSense, com ataques simulados.

Os IPs "da internet" usam as faixas reservadas para documentação (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
Rode:  python scripts/gerar_exemplo.py [caminho_de_saida]
"""
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

MESES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
WAN, LAN = "em0", "em1"
IP_WAN = "192.0.2.10"
SERVIDOR_WEB, SERVIDOR_RDP = "192.168.10.20", "192.168.10.30"
DEFAULT_DENY = ("82", "1000000103")
BLOQ_PRIVADOS = ("3", "12000")
PASS_HTTPS = ("15", "1700000001")
PASS_RDP = ("22", "1700000002")
BLOQ_LAN_SERVIDORES = ("101", "1700000050")
PASS_LAN = ("30", "1700000010")

rng = random.Random(2026)
linhas: list[tuple[datetime, str]] = []


def stamp(t: datetime) -> str:
    return f"{MESES[t.month - 1]} {t.day:2d} {t:%H:%M:%S}"


def v4(t, regra, iface, acao, direcao, proto, src, dst, sport, dport, flags="S"):
    r, tracker = regra
    if proto == "tcp":
        dados, pid, tam = f"{sport},{dport},0,{flags},{rng.randint(10**8, 4 * 10**9)},,{rng.choice([1024, 29200, 64240])},,mss", 6, 52
    elif proto == "udp":
        dados, pid, tam = f"{sport},{dport},{rng.randint(20, 120)}", 17, 80
    else:
        dados, pid, tam = f"request,{rng.randint(1, 60000)},1", 1, 84
    csv = (f"{r},,,{tracker},{iface},match,{acao},{direcao},4,0x0,,{rng.choice([52, 64, 117, 128, 239])},{rng.randint(1, 65000)},0,"
           f"{rng.choice(['DF', 'none'])},{pid},{proto},{tam},{src},{dst},{dados}")
    linhas.append((t, f"{stamp(t)} filterlog[{rng.randint(20000, 60000)}]: {csv}"))


def v6(t, regra, iface, acao, src, dst, dport):
    r, tracker = regra
    csv = f"{r},,,{tracker},{iface},match,{acao},in,6,0x00,0x00000,64,tcp,6,40,{src},{dst},{rng.randint(1024, 65000)},{dport},0,S,1,,64800,,mss"
    linhas.append((t, f"{stamp(t)} filterlog[{rng.randint(20000, 60000)}]: {csv}"))


def externo():
    return f"{rng.choice(['203.0.113', '198.51.100'])}.{rng.randint(1, 249)}"


def varredura(inicio, origem, destino, portas, duracao_s, regra=DEFAULT_DENY, iface=WAN, proto="tcp"):
    for i, porta in enumerate(portas):
        t = inicio + timedelta(seconds=duracao_s * i / max(1, len(portas) - 1))
        v4(t, regra, iface, "block", "in", proto, origem, destino, rng.randint(1024, 65000), porta)


fim = datetime(2026, 11, 2, 8, 0, 0)
t = datetime(2026, 11, 1, 18, 0, 0)

# ruído de fundo
while t < fim:
    for _ in range(rng.randint(1, 4)):
        quando = t + timedelta(seconds=rng.randint(0, 59))
        sorteio = rng.random()
        if sorteio < 0.40:    # internet batendo em portas comuns (bloqueado)
            v4(quando, DEFAULT_DENY, WAN, "block", "in", "tcp", externo(), IP_WAN, rng.randint(1024, 65000), rng.choice([23, 445, 8080, 5900, 1433, 80, 8443, 3306, 21]))
        elif sorteio < 0.55:  # ping / UDP aleatório
            v4(quando, DEFAULT_DENY, WAN, "block", "in", rng.choice(["icmp", "udp"]), externo(), IP_WAN, rng.randint(1024, 65000), rng.choice([123, 5060, 1900, 161]))
        elif sorteio < 0.75:  # site publicado (liberado)
            v4(quando, PASS_HTTPS, WAN, "pass", "in", "tcp", externo(), SERVIDOR_WEB, rng.randint(1024, 65000), 443, rng.choice(["S", "S", "SA"]))
        elif sorteio < 0.95:  # usuários da LAN
            v4(quando, PASS_LAN, LAN, "pass", "in", rng.choice(["tcp", "udp"]), f"192.168.10.{rng.randint(50, 120)}", rng.choice(["192.168.10.1", "198.51.100.8"]),
               rng.randint(1024, 65000), rng.choice([53, 443, 443, 80]))
        else:
            v6(quando, DEFAULT_DENY, WAN, "block", "2001:db8:abcd::" + format(rng.randint(1, 500), "x"), "2001:db8:1::10", rng.choice([22, 445, 3389]))
    t += timedelta(minutes=1)

# 1) varredura de portas vinda da internet
varredura(datetime(2026, 11, 1, 21, 12, 3), "203.0.113.50", IP_WAN, rng.sample(range(1, 1024), 60), 90)
# 2) varredura LENTA (fica abaixo do limite: não deve gerar achado)
varredura(datetime(2026, 11, 1, 22, 0, 0), "198.51.100.200", IP_WAN, [21, 22, 23, 25, 80, 110, 143, 443], 280)
# 3) máquina da LAN varrendo a rede de servidores na porta 445
for i in range(40):
    v4(datetime(2026, 11, 1, 23, 40, 0) + timedelta(seconds=3 * i), BLOQ_LAN_SERVIDORES, LAN, "block", "in", "tcp", "192.168.10.77", f"192.168.20.{10 + i}", rng.randint(1024, 65000), 445)
# 4) IP privado chegando pela WAN
for i in range(15):
    v4(datetime(2026, 11, 2, 1, 15, 0) + timedelta(seconds=20 * i), BLOQ_PRIVADOS, WAN, "block", "in", "tcp", "10.9.8.7", IP_WAN, rng.randint(1024, 65000), 80)
# 5) força bruta no RDP liberado para a internet
for i in range(60):
    v4(datetime(2026, 11, 2, 2, 30, 0) + timedelta(seconds=3 * i), PASS_RDP, WAN, "pass", "in", "tcp", "203.0.113.99", SERVIDOR_RDP, rng.randint(1024, 65000), 3389)
# 6) tentativas de SSH bloqueadas
for i in range(40):
    v4(datetime(2026, 11, 2, 4, 10, 0) + timedelta(seconds=6 * i), DEFAULT_DENY, WAN, "block", "in", "tcp", "203.0.113.140", IP_WAN, rng.randint(1024, 65000), 22)
# 7) o scanner de vulnerabilidades da própria empresa (use --ignorar 203.0.113.250/32)
varredura(datetime(2026, 11, 2, 6, 0, 0), "203.0.113.250", IP_WAN, rng.sample(range(1, 2000), 40), 60)

# linhas de outros serviços e uma linha quebrada, como num log de verdade
linhas.append((datetime(2026, 11, 1, 18, 30, 0), f"{stamp(datetime(2026, 11, 1, 18, 30, 0))} dhcpd[1234]: DHCPACK on 192.168.10.88 to aa:bb:cc:dd:ee:ff via em1"))
linhas.append((datetime(2026, 11, 1, 19, 0, 0), f"{stamp(datetime(2026, 11, 1, 19, 0, 0))} sshd[998]: Accepted publickey for admin from 192.168.10.5 port 51234 ssh2"))
linhas.append((datetime(2026, 11, 1, 19, 5, 0), f"{stamp(datetime(2026, 11, 1, 19, 5, 0))} filterlog[43210]: 82,,,quebrada,em0"))

linhas.sort(key=lambda x: x[0])
destino = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "data" / "filter_exemplo.log"
destino.parent.mkdir(parents=True, exist_ok=True)
destino.write_text("\n".join(l for _, l in linhas) + "\n", encoding="utf-8", newline="\n")
print(f"{len(linhas)} linhas gravadas em {destino}", file=sys.stderr)
