"""Saídas: texto no terminal, CSVs (Excel pt-BR) e um relatório HTML sem dependências externas.

Tudo que vem do log é tratado como não confiável: o HTML escapa tudo e o CSV neutraliza fórmulas.
"""
from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from .analise import BLOQUEIO, Resultado
from .leitor import Leitura

_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _fmt(dt) -> str:
    return dt.strftime("%d/%m/%Y %H:%M") if dt else "-"


def _pct(parte: int, total: int) -> str:
    return f"{100 * parte / total:.1f}%" if total else "0%"


def celula(valor):
    """Evita que uma célula vinda do log seja interpretada como fórmula pelo Excel."""
    if isinstance(valor, str) and valor.startswith(_FORMULA):
        return "'" + valor
    return valor


def resumo_texto(res: Resultado, leitura: Leitura, top: int = 10) -> str:
    b, total = res.bloqueios, res.total
    linhas = ["pfSense: análise do filterlog", "=" * 30,
              f"Período: {_fmt(res.primeiro)} a {_fmt(res.ultimo)}",
              f"Linhas lidas: {leitura.linhas} | aproveitadas: {leitura.validas} | formato inválido: {leitura.invalidas} | de outros serviços: {leitura.outras}",
              f"Registros: {total} | bloqueados: {b} ({_pct(b, total)}) | liberados: {res.acoes.get('pass', 0)}",
              "Interfaces: " + (", ".join(f"{i} ({n})" for i, n in res.interfaces.most_common()) or "-"), ""]
    gr = res.por_gravidade()
    linhas.append(f"ACHADOS ({len(res.achados)}): " + (", ".join(f"{g} {gr[g]}" for g in ("ALTA", "MÉDIA", "BAIXA", "INFO") if gr[g]) or "nenhum"))
    for a in res.achados[:50]:
        linhas.append(f"  [{a.gravidade}] {a.origem}: {a.detalhe}  ({_fmt(a.inicio)})")
    if len(res.achados) > 50:
        linhas.append(f"  ... e mais {len(res.achados) - 50} (veja achados.csv)")
    if res.top_origens:
        linhas += ["", f"Origens mais bloqueadas (top {top}):"]
        linhas += [f"  {ip:<40} {n:>7} bloqueios  {portas:>4} portas  ({escopo})" for ip, n, portas, escopo in res.top_origens]
    if res.top_portas:
        linhas += ["", "Portas de destino mais bloqueadas:"]
        linhas += [f"  {porta:>5}/{proto:<4} {servico:<16} {n:>7}" for porta, proto, servico, n in res.top_portas]
    if res.regras:
        linhas += ["", "Regras mais acionadas:"]
        linhas += [f"  regra {regra:<6} tracker {tracker or '-':<12} {acao:<7} {n:>7}" for regra, tracker, acao, n in res.regras]
    if res.portas_wan:
        linhas += ["", "Portas com tráfego liberado na WAN:"]
        linhas += [f"  {porta:>5} {servico:<16} {n:>7} conexões aceitas" for porta, servico, n in res.portas_wan]
    return "\n".join(linhas)


def escrever_csvs(res: Resultado, pasta: str, sep: str = ";") -> list[str]:
    destino = Path(pasta)
    destino.mkdir(parents=True, exist_ok=True)
    tabelas = {
        "achados.csv": (["gravidade", "tipo", "origem", "inicio", "fim", "valor", "detalhe"],
                        [[a.gravidade, a.tipo, a.origem, a.inicio.isoformat(" "), a.fim.isoformat(" "), a.valor, a.detalhe] for a in res.achados]),
        "top_origens.csv": (["origem", "bloqueios", "portas_distintas", "escopo"], [list(l) for l in res.top_origens]),
        "top_portas.csv": (["porta", "protocolo", "servico", "bloqueios"], [list(l) for l in res.top_portas]),
        "regras.csv": (["regra", "tracker", "acao", "registros"], [list(l) for l in res.regras]),
        "por_hora.csv": (["hora", "bloqueios", "liberados"], [[h.isoformat(" "), b, p] for h, b, p in res.por_hora]),
    }
    escritos = []
    for nome, (cabecalho, linhas) in tabelas.items():
        with open(destino / nome, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=sep)
            w.writerow(cabecalho)
            w.writerows([[celula(c) for c in linha] for linha in linhas])
        escritos.append(nome)
    return escritos


def para_json(res: Resultado, leitura: Leitura) -> str:
    return json.dumps({
        "periodo": [res.primeiro.isoformat() if res.primeiro else None, res.ultimo.isoformat() if res.ultimo else None],
        "leitura": {"linhas": leitura.linhas, "validas": leitura.validas, "invalidas": leitura.invalidas, "outras": leitura.outras},
        "registros": res.total, "bloqueios": res.bloqueios, "acoes": dict(res.acoes),
        "achados": [{"gravidade": a.gravidade, "tipo": a.tipo, "origem": a.origem, "inicio": a.inicio.isoformat(), "fim": a.fim.isoformat(),
                     "valor": a.valor, "detalhe": a.detalhe} for a in res.achados],
    }, ensure_ascii=False, indent=2)


_CSS = """
:root{--fundo:#F6F4EF;--cartao:#fff;--texto:#23212E;--suave:#6B6880;--linha:#E4E0D6;--alta:#B3261E;--media:#B26A00;--baixa:#2F6FAE;--info:#6B6880;--barra:#4C6FD0}
@media (prefers-color-scheme:dark){:root{--fundo:#16151D;--cartao:#1F1E29;--texto:#ECEAF4;--suave:#A29FB8;--linha:#34324A;--alta:#FF8A80;--media:#FFB74D;--baixa:#7FB4F0;--info:#A29FB8;--barra:#8EA6F5}}
*{box-sizing:border-box}body{margin:0;background:var(--fundo);color:var(--texto);font:15px/1.5 system-ui,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 48px}h1{margin:0 0 4px;font-size:24px}h2{margin:32px 0 10px;font-size:17px}
.sub{color:var(--suave);margin:0 0 20px}.cartoes{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.cartao{background:var(--cartao);border:1px solid var(--linha);border-radius:10px;padding:12px 14px}.cartao b{display:block;font-size:22px}.cartao span{color:var(--suave);font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--cartao);border:1px solid var(--linha);border-radius:10px;overflow:hidden;font-size:14px}
th,td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--linha);vertical-align:top}th{color:var(--suave);font-weight:600}tr:last-child td{border-bottom:0}
td.n{text-align:right;font-variant-numeric:tabular-nums}.sel{font-weight:700}.ALTA{color:var(--alta)}.MEDIA{color:var(--media)}.BAIXA{color:var(--baixa)}.INFO{color:var(--info)}
.barra{display:inline-block;height:8px;background:var(--barra);border-radius:4px;vertical-align:middle;min-width:2px}.vazio{color:var(--suave)}
.tabela-rolagem{overflow-x:auto}code{font-family:ui-monospace,Consolas,monospace;font-size:13px}
"""


def _t(valor) -> str:
    return html.escape(str(valor), quote=True)


def _tabela(cabecalhos, linhas, numericas=()):
    if not linhas:
        return '<p class="vazio">Nada para mostrar.</p>'
    cab = "".join(f"<th>{_t(c)}</th>" for c in cabecalhos)
    corpo = "".join("<tr>" + "".join(f'<td class="{"n" if i in numericas else ""}">{c}</td>' for i, c in enumerate(l)) + "</tr>" for l in linhas)
    return f'<div class="tabela-rolagem"><table><thead><tr>{cab}</tr></thead><tbody>{corpo}</tbody></table></div>'


def para_html(res: Resultado, leitura: Leitura) -> str:
    b, total = res.bloqueios, res.total
    gr = res.por_gravidade()
    cartoes = [(f"{total:,}".replace(",", "."), "registros"), (f"{b:,}".replace(",", "."), f"bloqueados ({_pct(b, total)})"),
               (f"{res.acoes.get('pass', 0):,}".replace(",", "."), "liberados"), (str(gr["ALTA"]), "achados de gravidade alta"), (str(len(res.achados)), "achados no total")]
    achados = _tabela(["Gravidade", "Origem", "O que foi visto", "Quando"],
                      [[f'<span class="sel {_t(a.gravidade.replace("É", "E"))}">{_t(a.gravidade)}</span>', f"<code>{_t(a.origem)}</code>", _t(a.detalhe), _t(_fmt(a.inicio))] for a in res.achados])
    maximo = max([n for _, n, _, _ in res.top_origens], default=1)
    origens = _tabela(["Origem", "Bloqueios", "", "Portas", "Escopo"],
                      [[f"<code>{_t(ip)}</code>", _t(n), f'<span class="barra" style="width:{max(2, int(120 * n / maximo))}px"></span>', _t(p), _t(e)] for ip, n, p, e in res.top_origens], numericas=(1, 3))
    portas = _tabela(["Porta", "Serviço", "Bloqueios"], [[f"{_t(p)}/{_t(pr)}", _t(s), _t(n)] for p, pr, s, n in res.top_portas], numericas=(2,))
    regras = _tabela(["Regra", "Tracker", "Ação", "Registros"], [[_t(r), _t(t or "-"), _t(a), _t(n)] for r, t, a, n in res.regras], numericas=(3,))
    horas_max = max([bl for _, bl, _ in res.por_hora], default=1) or 1
    horas = _tabela(["Hora", "Bloqueios", "", "Liberados"],
                    [[_t(h.strftime("%d/%m %H:00")), _t(bl), f'<span class="barra" style="width:{max(2, int(160 * bl / horas_max))}px"></span>', _t(p)] for h, bl, p in res.por_hora], numericas=(1, 3))
    wan = (_tabela(["Porta", "Serviço", "Conexões aceitas"], [[_t(p), _t(s), _t(n)] for p, s, n in res.portas_wan], numericas=(2,))
           if res.portas_wan else '<p class="vazio">Informe a interface WAN (--wan) para ver as portas liberadas para a internet.</p>')
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Análise do filterlog do pfSense</title><style>{_CSS}</style></head><body><main>
<h1>Análise do filterlog do pfSense</h1>
<p class="sub">{_t(_fmt(res.primeiro))} a {_t(_fmt(res.ultimo))} · {_t(leitura.validas)} de {_t(leitura.linhas)} linhas aproveitadas ({_t(leitura.invalidas)} com formato inválido)</p>
<div class="cartoes">{"".join(f'<div class="cartao"><b>{_t(v)}</b><span>{_t(r)}</span></div>' for v, r in cartoes)}</div>
<h2>Achados</h2>{achados}
<h2>Origens mais bloqueadas</h2>{origens}
<h2>Portas de destino mais bloqueadas</h2>{portas}
<h2>Portas liberadas na WAN</h2>{wan}
<h2>Regras mais acionadas</h2>{regras}
<h2>Bloqueios por hora</h2>{horas}
<p class="sub" style="margin-top:32px">Gerado por pfsense-log-analyzer. Os achados são heurísticas para apontar onde olhar, não prova de ataque.</p>
</main></body></html>"""
