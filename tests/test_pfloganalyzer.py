import bz2
import contextlib
import csv
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from pfloganalyzer import analise, cli, leitor, relatorio
from pfloganalyzer.analise import Analisador, Parametros, analisar, eh_local
from pfloganalyzer.leitor import Leitura, Registro, interpretar, ler_arquivos, ler_linhas

RAIZ = Path(__file__).resolve().parent.parent
EXEMPLO = RAIZ / "data" / "filter_exemplo.log"
T0 = datetime(2026, 11, 1, 20, 0, 0)

TCP4 = "82,,,1000000103,em0,match,block,in,4,0x0,,52,41234,0,none,6,tcp,52,203.0.113.50,192.0.2.10,44123,22,0,S,1000,,1024,,mss"
UDP4 = "82,,,1000000103,em0,match,block,in,4,0x0,,64,1,0,none,17,udp,80,203.0.113.7,192.0.2.10,5060,5060,60"
ICMP4 = "82,,,1000000103,em0,match,block,in,4,0x0,,64,1,0,none,1,icmp,84,203.0.113.7,192.0.2.10,request,1234,1"
TCP6 = "82,,,1000000103,em0,match,block,in,6,0x00,0x00000,64,tcp,6,40,2001:db8::1,2001:db8:1::10,50000,3389,0,S,1,,64800,,mss"


def reg(src="203.0.113.50", dst="192.0.2.10", dport=22, t=T0, acao="block", direcao="in", iface="em0", flags="S", proto="tcp", regra="82", tracker="1000000103"):
    return Registro(t, regra, tracker, iface, acao, direcao, 4, proto, src, dst, 40000, dport, flags)


class TestLeitor(unittest.TestCase):
    def ler(self, linha, ano=2026):
        lei = Leitura()
        return list(ler_linhas([linha], ano, lei)), lei

    def test_tcp_ipv4_bsd_sem_hostname(self):
        (r,), lei = self.ler(f"Nov  2 00:12:01 filterlog[4321]: {TCP4}")
        self.assertEqual((r.quando, r.regra, r.tracker, r.interface, r.acao, r.direcao), (datetime(2026, 11, 2, 0, 12, 1), "82", "1000000103", "em0", "block", "in"))
        self.assertEqual((r.versao, r.proto, r.origem, r.destino, r.porta_origem, r.porta_destino, r.flags), (4, "tcp", "203.0.113.50", "192.0.2.10", 44123, 22, "S"))
        self.assertEqual((lei.linhas, lei.validas, lei.invalidas, lei.outras), (1, 1, 0, 0))

    def test_variacoes_de_prefixo(self):
        for prefixo in ["Nov  2 00:12:01 pfSense filterlog[4321]: ", "Nov  2 00:12:01 pfSense.localdomain filterlog: ", "<134>Nov  2 00:12:01 pfSense filterlog[1]: "]:
            (r,), _ = self.ler(prefixo + TCP4)
            self.assertEqual(r.porta_destino, 22, prefixo)

    def test_rfc5424(self):
        (r,), _ = self.ler(f"<134>1 2026-11-02T00:12:01.123456-03:00 pfSense.localdomain filterlog 4321 - - {TCP4}")
        self.assertEqual((r.quando, r.porta_destino, r.origem), (datetime(2026, 11, 2, 0, 12, 1, 123456), 22, "203.0.113.50"))
        (r,), _ = self.ler(f"<134>1 2026-11-02T03:12:01Z host filterlog 1 - - {TCP4}")
        self.assertEqual(r.quando, datetime(2026, 11, 2, 3, 12, 1))

    def test_udp_icmp_ipv6(self):
        (u,), _ = self.ler(f"Nov  2 00:12:01 filterlog[1]: {UDP4}")
        self.assertEqual((u.proto, u.porta_destino, u.flags), ("udp", 5060, ""))
        (i,), _ = self.ler(f"Nov  2 00:12:01 filterlog[1]: {ICMP4}")
        self.assertEqual((i.proto, i.porta_origem, i.porta_destino), ("icmp", None, None))
        (v,), _ = self.ler(f"Nov  2 00:12:01 filterlog[1]: {TCP6}")
        self.assertEqual((v.versao, v.origem, v.destino, v.porta_destino), (6, "2001:db8::1", "2001:db8:1::10", 3389))

    def test_fragmento_sem_portas_ainda_conta(self):
        (r,), _ = self.ler("Nov  2 00:12:01 filterlog[1]: 82,,,1000000103,em0,match,block,in,4,0x0,,64,1,185,none,6,tcp,1500,203.0.113.7,192.0.2.10")
        self.assertEqual((r.proto, r.porta_destino), ("tcp", None))

    def test_linhas_invalidas_sao_contadas_e_nao_quebram(self):
        ruins = [
            "82,,,1000000103,em0",                                                    # curta
            TCP4.replace("203.0.113.50", "999.1.1.1"),                                # IP inválido
            TCP4.replace("44123,22", "44123,99999"),                                  # porta fora da faixa
            TCP4.replace(",block,in,4,", ",block,sideways,4,"),                        # direção inválida
            TCP4.replace(",block,in,4,", ",block,in,5,"),                              # versão inválida
            TCP4.replace("em0", "em0;<script>"),                                      # interface com lixo
            TCP4.replace("block", "BLOCK!!"),                                          # ação inválida
        ]
        for csv_ in ruins:
            regs, lei = self.ler(f"Nov  2 00:12:01 filterlog[1]: {csv_}")
            self.assertEqual((regs, lei.invalidas), ([], 1), csv_)

    def test_data_invalida_e_outros_servicos(self):
        regs, lei = self.ler(f"Foo 99 25:61:61 filterlog[1]: {TCP4}")
        self.assertEqual((regs, lei.invalidas), ([], 1))
        regs, lei = self.ler("Nov  2 00:12:01 dhcpd[1]: DHCPACK on 192.168.10.88 to aa:bb:cc via em1")
        self.assertEqual((regs, lei.outras, lei.invalidas), ([], 1, 0))

    def test_virada_de_ano(self):
        linhas = [f"Dec 31 23:59:58 filterlog[1]: {TCP4}", f"Jan  1 00:00:02 filterlog[1]: {TCP4}", f"Jan  1 00:00:03 filterlog[1]: {TCP4}"]
        anos = [r.quando for r in ler_linhas(linhas, 2026)]
        self.assertEqual([a.year for a in anos], [2026, 2027, 2027])

    def test_ordem_normal_nao_vira_o_ano(self):
        linhas = [f"Nov  2 00:00:01 filterlog[1]: {TCP4}", f"Nov  2 00:00:00 filterlog[1]: {TCP4}", f"Oct 31 23:59:59 filterlog[1]: {TCP4}"]
        self.assertEqual({r.quando.year for r in ler_linhas(linhas, 2026)}, {2026})

    def test_formatos_de_arquivo_e_relogio_compartilhado(self):
        with tempfile.TemporaryDirectory() as d:
            a, b, c = Path(d, "a.log"), Path(d, "b.log.0"), Path(d, "c.txt")   # extensões enganosas de propósito
            a.write_bytes(gzip.compress(f"Dec 31 23:59:58 filterlog[1]: {TCP4}\n".encode()))
            b.write_bytes(bz2.compress(f"Jan  1 00:00:02 filterlog[1]: {TCP4}\n".encode()))
            c.write_bytes(f"Jan  1 00:00:05 filterlog[1]: {TCP4}\r\n".encode())
            regs = list(ler_arquivos([str(a), str(b), str(c)], 2026))
            self.assertEqual([r.quando.year for r in regs], [2026, 2027, 2027])

    def test_bytes_invalidos_nao_quebram(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "x.log")
            p.write_bytes(b"Nov  2 00:00:00 sshd[1]: caf\xe9 \xff\xfe\n" + f"Nov  2 00:00:01 filterlog[1]: {TCP4}\n".encode())
            lei = Leitura()
            self.assertEqual(len(list(ler_arquivos([str(p)], 2026, lei))), 1)
            self.assertEqual(lei.outras, 1)

    def test_arquivo_inexistente(self):
        with self.assertRaises(FileNotFoundError):
            list(ler_arquivos(["/nao/existe.log"], 2026))

    def test_interpretar_direto(self):
        self.assertIsNone(interpretar("", T0))
        self.assertIsNotNone(interpretar(TCP4, T0))


class TestAnalise(unittest.TestCase):
    def portas(self, n, passo_s=1, **kw):
        return [reg(dport=1000 + i, t=T0 + timedelta(seconds=passo_s * i), **kw) for i in range(n)]

    def achados(self, regs, **kw):
        return analisar(regs, Parametros(**kw)).achados

    def tipos(self, regs, **kw):
        return [a.tipo for a in self.achados(regs, **kw)]

    def test_varredura_de_portas_no_limite(self):
        self.assertEqual(self.tipos(self.portas(14)), [])
        self.assertEqual(self.tipos(self.portas(15)), ["varredura_portas"])

    def test_varredura_respeita_a_janela(self):
        # 15 portas, uma a cada 60 s, janela de 300 s: nunca há 15 ao mesmo tempo
        self.assertEqual(self.tipos(self.portas(15, passo_s=60)), [])
        self.assertEqual(self.tipos(self.portas(15, passo_s=60), janela=3600), ["varredura_portas"])

    def test_borda_exata_da_janela(self):
        dentro = [reg(dport=1000 + i, t=T0 + timedelta(seconds=300 * i / 14)) for i in range(15)]    # 15 portas em exatamente 300 s
        self.assertEqual(self.tipos(dentro), ["varredura_portas"])
        fora = [reg(dport=1000 + i, t=T0 + timedelta(seconds=301 * i / 14)) for i in range(15)]      # 301 s: a primeira já saiu
        self.assertEqual(self.tipos(fora), [])

    def test_varredura_de_hosts(self):
        regs = [reg(dst=f"192.168.20.{i}", dport=445, t=T0 + timedelta(seconds=i)) for i in range(10)]
        self.assertEqual(self.tipos(regs[:9]), [])
        self.assertEqual(self.tipos(regs), ["varredura_hosts"])

    def test_so_bloqueio_de_entrada_conta(self):
        self.assertEqual(self.tipos([dataclass_replace(r, acao="pass") for r in self.portas(30)]), [])
        self.assertEqual(self.tipos([dataclass_replace(r, direcao="out") for r in self.portas(30)]), [])
        self.assertEqual(self.tipos([dataclass_replace(r, acao="reject") for r in self.portas(30)]), ["varredura_portas"])

    def test_origens_diferentes_nao_se_somam(self):
        regs = [reg(src=f"203.0.113.{i}", dport=1000 + i, t=T0 + timedelta(seconds=i)) for i in range(40)]
        self.assertEqual(self.tipos(regs), [])

    def test_gravidade_externa_e_interna(self):
        grande = self.portas(45)
        self.assertEqual(self.achados(self.portas(15))[0].gravidade, "BAIXA")
        self.assertEqual(self.achados(grande)[0].gravidade, "MÉDIA")
        interna = [dataclass_replace(r, src_=None) if False else Registro(r.quando, r.regra, r.tracker, "em1", r.acao, r.direcao, 4, "tcp", "192.168.10.77", r.destino, 1, r.porta_destino, "S") for r in self.portas(15)]
        self.assertEqual(self.achados(interna, wan=frozenset({"em0"}))[0].gravidade, "ALTA")
        self.assertEqual(self.achados(interna)[0].gravidade, "ALTA")     # sem --wan, decide pelo endereço

    def test_ignorar_rede(self):
        import ipaddress
        regs = self.portas(30)
        self.assertEqual(self.tipos(regs, ignorar=(ipaddress.ip_network("203.0.113.0/24"),)), [])
        self.assertEqual(self.tipos(regs, ignorar=(ipaddress.ip_network("203.0.114.0/24"),)), ["varredura_portas"])

    def test_tentativas_repetidas_so_conexao_nova(self):
        syn = [reg(dport=3389, flags="S", t=T0 + timedelta(seconds=i)) for i in range(20)]
        self.assertEqual(self.tipos(syn[:19]), [])
        self.assertEqual(self.tipos(syn), ["tentativas_repetidas"])
        ack = [dataclass_replace(r, flags="A") for r in syn]
        self.assertEqual(self.tipos(ack), [])
        porta_comum = [dataclass_replace(r, dport=8080) for r in syn]
        self.assertEqual(self.tipos(porta_comum), [])

    def test_tentativas_gravidade(self):
        syn = [reg(dport=3389, t=T0 + timedelta(seconds=i)) for i in range(25)]
        self.assertEqual(self.achados(syn)[0].gravidade, "BAIXA")                                    # só bloqueios
        liberado = [dataclass_replace(r, acao="pass") for r in syn]
        self.assertEqual(self.achados(liberado)[0].gravidade, "ALTA")                                # serviço aberto sendo atacado
        interno = [Registro(r.quando, "1", "", "em1", "block", "in", 4, "tcp", "192.168.10.9", r.destino, 1, 3389, "S") for r in syn]
        self.assertEqual(self.achados(interno)[0].gravidade, "MÉDIA")

    def test_porta_exposta_na_wan(self):
        p = [reg(dport=3389, acao="pass", regra="22", tracker="17", t=T0 + timedelta(seconds=i)) for i in range(3)]
        a = [x for x in self.achados(p, wan=frozenset({"em0"})) if x.tipo == "porta_exposta"]
        self.assertEqual((len(a), a[0].gravidade, a[0].valor, a[0].origem), (1, "ALTA", 3, "regra 22"))
        self.assertIn("RDP", a[0].detalhe)
        self.assertEqual([x for x in self.achados(p) if x.tipo == "porta_exposta"], [])                                  # sem --wan não sabe o que é WAN
        self.assertEqual([x for x in self.achados([dataclass_replace(r, iface="em1") for r in p], wan=frozenset({"em0"})) if x.tipo == "porta_exposta"], [])
        web = [dataclass_replace(r, dport=443) for r in p]
        self.assertEqual([x for x in self.achados(web, wan=frozenset({"em0"})) if x.tipo == "porta_exposta"], [])

    def test_portas_wan_liberadas_no_resultado(self):
        regs = [reg(dport=443, acao="pass")] * 3 + [reg(dport=3389, acao="pass")]
        self.assertEqual(analisar(regs, Parametros(wan=frozenset({"em0"}))).portas_wan, [(443, "HTTPS", 3), (3389, "RDP", 1)])
        self.assertEqual(analisar(regs).portas_wan, [])

    def test_ip_privado_na_wan(self):
        regs = [reg(src="10.9.8.7", t=T0 + timedelta(seconds=i)) for i in range(4)]
        a = self.achados(regs, wan=frozenset({"em0"}))
        self.assertEqual([(x.tipo, x.gravidade, x.valor) for x in a], [("ip_privado_na_wan", "MÉDIA", 4)])
        self.assertEqual(self.achados(regs), [])                                                      # sem --wan não há como saber
        self.assertEqual(self.achados([dataclass_replace(r, src="203.0.113.5") for r in regs], wan=frozenset({"em0"})), [])

    def test_eh_local(self):
        for ip in ["10.1.1.1", "172.16.5.5", "172.31.255.255", "192.168.0.1", "127.0.0.1", "169.254.1.1", "fe80::1", "fd00::1", "::1"]:
            self.assertTrue(eh_local(ip), ip)
        for ip in ["192.0.2.1", "203.0.113.5", "198.51.100.9", "172.32.0.1", "8.8.8.8", "2001:db8::1", "100.64.0.1"]:
            self.assertFalse(eh_local(ip), ip)

    def test_ordem_dos_achados_e_contagens(self):
        regs = self.portas(15) + [reg(dport=3389, acao="pass", regra="22", tracker="9", t=T0 + timedelta(minutes=10, seconds=i)) for i in range(2)]
        r = analisar(regs, Parametros(wan=frozenset({"em0"})))
        self.assertEqual([a.gravidade for a in r.achados], ["ALTA", "BAIXA"])
        self.assertEqual((r.total, r.bloqueios, r.acoes["pass"]), (17, 15, 2))
        self.assertEqual(r.por_gravidade()["ALTA"], 1)

    def test_rankings_e_hora(self):
        regs = [reg(src="203.0.113.1", dport=22)] * 3 + [reg(src="203.0.113.2", dport=22)] + [reg(src="203.0.113.2", dport=80, t=T0 + timedelta(hours=1), acao="pass")]
        r = analisar(regs)
        self.assertEqual(r.top_origens[0], ("203.0.113.1", 3, 1, "externa"))
        self.assertEqual(r.top_portas[0], (22, "tcp", "SSH", 4))
        self.assertEqual(r.por_hora, [(T0, 4, 0), (T0 + timedelta(hours=1), 0, 1)])

    def test_memoria_da_janela_e_limpeza(self):
        a = Analisador(Parametros(limite_portas=10**9, limite_hosts=10**9))
        for i in range(10000):
            a.registrar(reg(dport=1, t=T0 + timedelta(milliseconds=i)))
        self.assertLessEqual(len(a._janelas["203.0.113.50"].eventos), analise._MAX_EVENTOS_POR_ORIGEM)
        a.registrar(reg(src="203.0.113.99", t=T0 + timedelta(hours=1)))
        a._limpar(T0 + timedelta(hours=1))
        self.assertEqual(list(a._janelas), ["203.0.113.99"])

    def test_registros_fora_de_ordem_nao_quebram(self):
        regs = self.portas(20)
        regs.reverse()
        analisar(regs)


def dataclass_replace(r, **kw):
    campos = dict(quando=r.quando, regra=r.regra, tracker=r.tracker, interface=r.interface, acao=r.acao, direcao=r.direcao, versao=r.versao, proto=r.proto,
                  origem=r.origem, destino=r.destino, porta_origem=r.porta_origem, porta_destino=r.porta_destino, flags=r.flags)
    mapa = {"iface": "interface", "src": "origem", "dport": "porta_destino"}
    for k, v in kw.items():
        campos[mapa.get(k, k)] = v
    return Registro(**campos)


class TestRelatorio(unittest.TestCase):
    def resultado(self):
        regs = [reg(dport=1000 + i, t=T0 + timedelta(seconds=i)) for i in range(20)]
        lei = Leitura()
        lei.linhas = lei.validas = 20
        return analisar(regs, Parametros(wan=frozenset({"em0"}))), lei

    def test_celula_neutraliza_formulas(self):
        for perigo in ["=SOMA(A1)", "+1", "-1+2", "@cmd", "\t=1"]:
            self.assertTrue(relatorio.celula(perigo).startswith("'"), perigo)
        self.assertEqual(relatorio.celula("203.0.113.5"), "203.0.113.5")
        self.assertEqual(relatorio.celula(-5), -5)

    def test_html_escapa_tudo(self):
        res, lei = self.resultado()
        res.achados[0].detalhe = '<img src=x onerror="alert(1)">'
        res.achados[0].origem = "<script>alert(2)</script>"
        res.interfaces["<b>"] = 1
        res.top_portas.append((1, "<i>", "<u>", 1))
        html = relatorio.para_html(res, lei)
        for cru in ["<img src=x", "<script>alert", "<i>", "<u>"]:
            self.assertNotIn(cru, html)
        self.assertIn("&lt;img src=x", html)

    def test_html_sem_recursos_externos(self):
        res, lei = self.resultado()
        html = relatorio.para_html(res, lei)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<script", html)

    def test_csvs_e_json(self):
        res, lei = self.resultado()
        res.achados[0].detalhe = "=HYPERLINK(\"x\")"
        with tempfile.TemporaryDirectory() as d:
            nomes = relatorio.escrever_csvs(res, d)
            self.assertIn("achados.csv", nomes)
            bruto = Path(d, "achados.csv").read_bytes()
            self.assertTrue(bruto.startswith(b"\xef\xbb\xbf"))                 # BOM: Excel pt-BR abre com acento certo
            linhas = list(csv.reader(io.StringIO(bruto.decode("utf-8-sig")), delimiter=";"))
            self.assertEqual(linhas[0][0], "gravidade")
            self.assertTrue(linhas[1][-1].startswith("'="))
        dados = json.loads(relatorio.para_json(res, lei))
        self.assertEqual(dados["registros"], 20)
        self.assertEqual(dados["achados"][0]["tipo"], "varredura_portas")

    def test_texto(self):
        res, lei = self.resultado()
        texto = relatorio.resumo_texto(res, lei)
        for trecho in ["ACHADOS (1)", "[BAIXA]", "203.0.113.50", "Linhas lidas: 20"]:
            self.assertIn(trecho, texto)


class TestCLI(unittest.TestCase):
    def rodar(self, *args, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        antigo = sys.stdin
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    codigo = cli.main(list(args))
                except SystemExit as e:
                    codigo = e.code
        finally:
            sys.stdin = antigo
        return codigo, out.getvalue(), err.getvalue()

    def test_exemplo_completo(self):
        with tempfile.TemporaryDirectory() as d:
            codigo, out, _ = self.rodar(str(EXEMPLO), "--ano", "2026", "--wan", "em0", "--saida", d, "--html")
            self.assertEqual(codigo, 0)
            self.assertIn("RDP (porta 3389) liberado na WAN", out)
            self.assertIn("192.168.10.77", out)
            self.assertNotIn("198.51.100.200:", out)                         # varredura lenta: abaixo do limite
            for nome in ["achados.csv", "top_origens.csv", "top_portas.csv", "regras.csv", "por_hora.csv", "resumo.json", "relatorio.html"]:
                self.assertTrue(Path(d, nome).is_file(), nome)

    def test_falhar_se_alta(self):
        self.assertEqual(self.rodar(str(EXEMPLO), "--ano", "2026", "--wan", "em0", "--falhar-se-alta")[0], 2)
        self.assertEqual(self.rodar(str(EXEMPLO), "--ano", "2026", "--wan", "em0")[0], 0)

    def test_ignorar_remove_achado(self):
        _, antes, _ = self.rodar(str(EXEMPLO), "--ano", "2026", "--wan", "em0")
        _, depois, _ = self.rodar(str(EXEMPLO), "--ano", "2026", "--wan", "em0", "--ignorar", "203.0.113.250/32")
        self.assertIn("[BAIXA] 203.0.113.250", antes)
        self.assertNotIn("[BAIXA] 203.0.113.250", depois)

    def test_limites_mudam_o_resultado(self):
        _, out, _ = self.rodar(str(EXEMPLO), "--ano", "2026", "--limite-portas", "5")
        self.assertIn("198.51.100.200", out.split("Origens mais bloqueadas")[0])     # com limite 5 a varredura lenta passa a aparecer

    def test_entrada_padrao(self):
        codigo, out, _ = self.rodar("-", "--ano", "2026", stdin=f"Nov  2 00:12:01 filterlog[1]: {TCP4}\n")
        self.assertEqual(codigo, 0)
        self.assertIn("Registros: 1", out)

    def test_erros_de_uso_saem_com_1(self):
        self.assertEqual(self.rodar("/nao/existe.log")[0], 1)
        self.assertEqual(self.rodar(str(EXEMPLO), "--html")[0], 1)
        self.assertEqual(self.rodar(str(EXEMPLO), "--janela", "0")[0], 1)
        self.assertEqual(self.rodar(str(EXEMPLO), "--ignorar", "nao-e-ip")[0], 1)
        codigo, _, err = self.rodar("-", stdin="lixo qualquer\nsem filterlog\n")
        self.assertEqual(codigo, 1)
        self.assertIn("filter.log", err)

    def _rodar_modulo(self, codificacao):
        """Roda `python -m pfloganalyzer` num processo filho com a codificação de console dada (o Windows usa cp1252 por padrão)."""
        env = {**os.environ, "PYTHONIOENCODING": codificacao}
        return subprocess.run([sys.executable, "-m", "pfloganalyzer", str(EXEMPLO), "--ano", "2026"],
                              cwd=RAIZ, capture_output=True, env=env)

    def test_como_modulo(self):
        r = self._rodar_modulo("utf-8")
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        self.assertIn("ACHADOS", r.stdout.decode("utf-8"))

    def test_console_com_codificacao_limitada_nao_quebra(self):
        """Console cp1252 (padrão do Windows) ou até ASCII puro: a saída degrada com '?', nunca com traceback."""
        for codificacao in ("cp1252", "ascii"):
            with self.subTest(codificacao=codificacao):
                r = self._rodar_modulo(codificacao)
                self.assertEqual(r.returncode, 0, r.stderr.decode("ascii", "replace"))
                self.assertIn(b"ACHADOS", r.stdout)

    def test_gerador_e_deterministico(self):
        """O exemplo versionado bate com o que o gerador produz (ignora LF/CRLF, que o git do Windows pode trocar) e o gerador não mexe no arquivo versionado."""
        antes = EXEMPLO.read_bytes()
        with tempfile.TemporaryDirectory() as d:
            saida = Path(d, "novo.log")
            r = subprocess.run([sys.executable, str(RAIZ / "scripts" / "gerar_exemplo.py"), str(saida)], cwd=RAIZ, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(saida.read_bytes().replace(b"\r\n", b"\n"), antes.replace(b"\r\n", b"\n"))
        self.assertEqual(EXEMPLO.read_bytes(), antes)


if __name__ == "__main__":
    unittest.main()
