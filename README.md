# pfsense-log-analyzer

Lê o log do firewall do **pfSense** (`filterlog`) e aponta o que merece atenção: varreduras de portas e de hosts, tentativas repetidas contra serviços sensíveis (RDP, SSH, SMB...), portas perigosas liberadas para a internet e IPs privados chegando pela WAN. Python 3.10+, só biblioteca padrão, sem instalar nada.

> Todos os dados em `data/` são **fictícios** (IPs das faixas reservadas para documentação). Não publique logs reais: eles têm endereços da sua rede.

## O que ele detecta

| Achado | Como é decidido | Gravidade |
|---|---|---|
| Varredura de portas | origem com bloqueios em ≥ 15 portas distintas dentro de 5 min | BAIXA (internet), MÉDIA (≥ 3× o limite), ALTA (origem interna) |
| Varredura de hosts | origem com bloqueios em ≥ 10 destinos distintos dentro de 5 min | idem |
| Tentativas repetidas | ≥ 20 conexões novas (TCP só com flag `S`) ao mesmo serviço sensível em 5 min | ALTA se o firewall deixou passar, BAIXA se bloqueou, MÉDIA se a origem é interna |
| Porta exposta | regra que **libera** na WAN entrada para porta sensível (SSH, RDP, SMB, Telnet, VNC, bancos...) | ALTA |
| IP privado na WAN | origem RFC 1918/loopback/link-local chegando pela interface WAN | MÉDIA |

Os limites e a janela são ajustáveis. Além dos achados, gera rankings de origens, portas e regras mais acionadas e a contagem de bloqueios por hora.

## Uso

```bash
python -m pfloganalyzer filter.log --ano 2026 --wan em0
```

Com os dados de exemplo e todos os relatórios:

```bash
python -m pfloganalyzer data/filter_exemplo.log --ano 2026 --wan em0 --saida saida --html
```

Trecho da saída:

```
ACHADOS (8): ALTA 3, MÉDIA 3, BAIXA 2
  [ALTA] regra 22: RDP (porta 3389) liberado na WAN: 60 conexões aceitas de 1 origem(ns) (tracker 1700000002)
  [ALTA] 203.0.113.99: 60 conexões novas a RDP (porta 3389) em até 5 min; serviço liberado no firewall
  [ALTA] 192.168.10.77: 40 destinos diferentes bloqueados em até 5 min
  [MÉDIA] 203.0.113.50: 60 portas diferentes bloqueadas em até 5 min
  [MÉDIA] 10.9.8.7: IP privado chegando pela WAN (em0), 15 pacotes bloqueados
```

### Como pegar o log

O arquivo é `/var/log/filter.log` do pfSense. Copie por SCP ou pelo Diagnostics > Edit File. Em versões antigas do pfSense o arquivo é circular (clog); nesse caso converta antes com `clog /var/log/filter.log > filter.txt`. Os arquivos rotacionados (`.gz`, `.bz2`) também são lidos, e vários arquivos podem ser passados juntos, **do mais antigo ao mais novo**.

### Opções

| Opção | Função |
|---|---|
| `ARQUIVO [...]` | um ou mais logs (texto, gzip ou bzip2); `-` lê da entrada padrão |
| `--ano` | ano das linhas (o syslog BSD não traz ano). Padrão: ano atual. O ano avança sozinho se o log atravessar dezembro/janeiro |
| `--wan IFACE` | interface WAN (repetível). **Liga** as checagens de porta exposta e IP privado na WAN |
| `--janela`, `--limite-portas`, `--limite-hosts`, `--limite-tentativas` | ajustam as heurísticas |
| `--ignorar IP/REDE [...]` | origens que não geram achados (ex.: o seu scanner de vulnerabilidades) |
| `--top N` | tamanho dos rankings |
| `--saida PASTA` | grava `achados.csv`, `top_origens.csv`, `top_portas.csv`, `regras.csv`, `por_hora.csv`, `resumo.json` |
| `--html` | grava também `relatorio.html` (precisa de `--saida`) |
| `--sep` | separador dos CSVs (padrão `;`, abre direto no Excel pt-BR) |
| `--falhar-se-alta` | sai com código 2 se houver achado ALTA (útil em rotina agendada) |

Códigos de saída: `0` ok, `1` erro de uso ou de arquivo, `2` achado ALTA (com `--falhar-se-alta`).

## Formato lido

Cada linha de `filterlog` é um CSV dentro do syslog, conforme a documentação oficial do Netgate ([Raw Filter Log Format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html)): campos comuns (regra, tracker, interface, ação, direção, versão do IP), depois IPv4 ou IPv6 e depois TCP, UDP ou ICMP. São aceitos o formato BSD (`Nov  2 00:12:01 filterlog[4321]: ...`, com ou sem hostname) e o RFC 5424 (`<134>1 2026-11-02T00:12:01-03:00 host filterlog 4321 - - ...`). Linhas de outros serviços são ignoradas, e linhas de `filterlog` fora do formato são contadas e informadas no relatório, sem derrubar a análise.

## Decisões de projeto

- **Uma passada, memória limitada**: o log é lido em fluxo e cada origem guarda no máximo 4000 eventos recentes. Em teste com 1 milhão de linhas, a análise levou cerca de 36 s e ~47 MB de memória (máquina de desenvolvimento; o seu tempo pode variar).
- **Só tráfego de entrada** (`in`) entra nas varreduras e nas tentativas: é o que o firewall viu chegando em cada interface.
- **Tudo que vem do log é tratado como não confiável**: IPs, portas e nomes são validados na leitura, o HTML escapa tudo e não usa script nem recurso externo, e os CSVs neutralizam células que o Excel leria como fórmula.
- **Funciona offline**: não consulta reputação de IP nem geolocalização.

## Limitações (leia antes de confiar)

- **São heurísticas, não um IDS.** Um achado diz onde olhar, não prova ataque. Falsos positivos acontecem (ex.: um computador da LAN com muitos bloqueios legítimos parece varredura de hosts), e varreduras **lentas** (abaixo do limite na janela) não são detectadas.
- Só enxerga o que o firewall **registra**: regras com log desligado não aparecem, e "porta exposta" depende de a regra de liberação estar logando.
- Foi construído e testado com dados fictícios seguindo a documentação oficial. **Ainda não foi validado contra logs reais de várias versões do pfSense**; se algum formato falhar, a contagem de "formato inválido" no relatório mostra quantas linhas ficaram de fora.
- Não interpreta CARP nem os detalhes de cada tipo de ICMP (o pacote conta, mas sem tipo).

## Testes

```bash
python -m unittest discover -s tests -v
```

44 testes: leitura (BSD, RFC 5424, IPv4/IPv6, TCP/UDP/ICMP, linhas quebradas, gzip/bzip2, virada de ano), cada tipo de achado e seus limites (inclusive a borda exata da janela), gravidades, limpeza de memória, escape do HTML, CSV seguro e a linha de comando de ponta a ponta. Os dados de exemplo são gerados de forma determinística por `scripts/gerar_exemplo.py`.

## Licença

MIT, veja `LICENSE`.
