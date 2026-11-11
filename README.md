# 🚩 FIAP Global Solution — CTF Wargames: Forense Digital & DFIR (3º Semestre)

> Repositório com a documentação técnica e os write-ups da resolução de 15 desafios de **Capture The Flag (CTF)** de análise forense disponibilizados na plataforma Wargames. Este projeto compõe a avaliação Global Solution do curso de **Defesa Cibernética** da FIAP (2026).

> 🔒 **Publicado durante o CTF (05/11/2026 a 13/11/2026).** As flags e os valores finais de cada resposta aparecem ocultos (`██████`) até o encerramento, em **13/11/2026 às 23h59**. A metodologia, as ferramentas e os comandos estão completos. Depois do encerramento, as respostas serão adicionadas a este repositório.

---

## 📌 1. Visão Geral do Projeto

* **Instituição:** Faculdade de Informática e Administração Paulista (FIAP).
* **Curso:** Defesa Cibernética (3º Semestre - 2026).
* **Autor:** Pedro Henrique Ferrante Prado.
* **Coorientador:** André Luis Cirino.
* **Plataforma:** Wargames (CTF Global Solution, FIAP 2TDCOR), de 05/11/2026 a 13/11/2026.
* **Domínios Explorados:** Forense de logs do Windows (Sysmon/EVTX), Forense de Memória, Forense de Disco (ext2, ext3 e NTFS), Imagem Lógica AD1, Análise de Linha do Tempo, Resposta a Incidentes e MITRE ATT&CK.

---

## 🛠️ 2. Stack de Ferramentas & Utilitários

| Domínio | Ferramentas Utilizadas | Aplicação Prática no CTF |
| :--- | :--- | :--- |
| **Logs do Windows** | PowerShell (`Get-WinEvent`), Visualizador de Eventos, Sysmon (eventos 1, 3 e 22) | Triagem de EVTX, correlação por Record ID, contagem por Event ID e extração de campos pelo XML do evento. |
| **Forense de Memória** | Volatility 3 (`windows.info`, `pslist`, `envars`), `strings`, `grep`, `xxd`, Python | Identificação do SO, processos e variáveis de ambiente; recuperação de e-mail e de registros `.evt` por assinatura. |
| **Disco Linux (ext2/ext3)** | The Sleuth Kit (`mmls`, `fls`, `icat`, `istat`, `tsk_recover`), `mount -o ro,loop,noload`, `tar`, `md5sum` | Partições, inodes, extração e hash em lote, leitura de `auth.log` e de scripts de rootkit. |
| **Disco Windows (NTFS)** | The Sleuth Kit, `scripts/jl_min.py` | `$MFT`, comparação `$SI` x `$FN` (timestomping) e Jump Lists (`DestList` e AppID). |
| **Imagem Lógica** | `scripts/ad1_min.py`, `sha256sum`, 7-Zip | Leitura da árvore de um AD1 e extração dos artefatos `.7z`. |
| **Tratamento de Dados** | `grep`, `awk`, `sort`, `uniq`, `date` (`TZ`) | Contagens, filtros e conversão de fuso horário. |

---

## 🔍 3. Relatório Técnico dos Desafios (Write-ups)

> Os comandos dos write-ups reproduzem a lógica de cada etapa. Nomes de pastas de saída e caminhos podem variar conforme o ambiente.

### 🪟 3.1 Forense de Logs do Windows (Sysmon / EVTX)

#### 01 · Shadow Wire
* **Artefato:** `c2.evtx` (Sysmon).
* **Vetor:** Executável com metadados de outro programa (`OriginalFileName = ab.exe`) que se comunica com um servidor C2 na porta 4444.
* **Metodologia:** Correlação dos Event IDs 22 (DNS), 1 (criação de processo) e 3 (conexão) por Record ID, com extração dos campos pelo XML (`Get-WinEvent`).
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-sysmon-evtx/shadow-wire/`](forense-sysmon-evtx/shadow-wire/writeup.md)

#### 02 · Black Tide
* **Artefato:** `c2_1.evtx` (o mesmo log do desafio anterior, confirmado por SHA-256).
* **Vetor:** Download de ferramenta maliciosa (T1105) sem evento de criação de arquivo no Sysmon.
* **Metodologia:** Linha do tempo DNS do Edge, criação do processo e conexão de rede; o host infectado vem do `SourceIp` do Event ID 3.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-sysmon-evtx/black-tide/`](forense-sysmon-evtx/black-tide/writeup.md)

#### 13 · Operação DFIR
* **Artefato:** `log.evtx` (74.970 registros, servidor Windows 2019).
* **Vetor:** Força bruta contra o RDP (T1110 e T1021.001) com mais de 70 mil conexões de entrada na porta 3389.
* **Metodologia:** Contagem de Event IDs 1 e 3 com `-FilterXPath`; localização do evento por horário, resolvendo a diferença de fuso entre o enunciado (UTC-2) e a máquina de análise (UTC-3).
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-sysmon-evtx/operacao-dfir/`](forense-sysmon-evtx/operacao-dfir/writeup.md)

### 🧠 3.2 Forense de Memória (RAM)

#### 03 · Silent Mail
* **Artefato:** `email.mem` (1 GiB).
* **Vetor:** E-mail suspeito composto no Mozilla Thunderbird, cujos fragmentos permanecem na RAM.
* **Metodologia:** `strings -a` e `grep` por cabeçalhos RFC 5322 (`From`, `To`, `Subject`, `Date`), com contexto (`-B` e `-A`) para reconstruir a mensagem.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-de-memoria/silent-mail/`](forense-de-memoria/silent-mail/writeup.md)

#### 04 · Operation Ghost Letter
* **Artefato:** `email.mem` (o mesmo do Silent Mail).
* **Vetor:** Linha do tempo de um e-mail com o mesmo instante em horário local (`Date`) e em UTC (linha mbox `From -`).
* **Metodologia:** Cabeçalho `Date` confirmado pela linha mbox e pelos registros internos do cliente, com a escolha explícita do fuso da resposta.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-de-memoria/operation-ghost-letter/`](forense-de-memoria/operation-ghost-letter/writeup.md)

#### 05 · Deep Memory
* **Artefato:** `desafio.mem` (256 MiB, Windows XP SP3).
* **Vetor:** Valor em hexadecimal escondido em uma variável de ambiente de processo.
* **Metodologia:** `windows.info`, `windows.pslist` (nada suspeito) e `windows.envars` filtrado por `CHALLENGE`, seguido de `xxd -r -p`.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-de-memoria/deep-memory/`](forense-de-memoria/deep-memory/writeup.md)

#### 06 · Print Strike
* **Artefato:** `win.mem` (256 MiB, Windows XP SP3).
* **Vetor:** Log `.evt` do ThinPrint (VMware Tools) preservado nas páginas de memória.
* **Metodologia:** Recuperação dos registros pela assinatura `LfLe` (`scripts/evt_mini.py`) e conversão do horário de UTC para UTC-3.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-de-memoria/print-strike/`](forense-de-memoria/print-strike/writeup.md)

### 🐧 3.3 Forense de Disco Linux (ext2 / ext3)

#### 07 · Brute force Legacy
* **Artefato:** `server.img` (ext3, Debian 5.0.7, host `victoria`).
* **Vetor:** Força bruta SSH contra um usuário inexistente, a partir de `192.168.56.1`.
* **Metodologia:** Imagem montada em somente leitura (`ro,loop,noload`) e contagem de `Failed none` e `Failed password` no `auth.log`, sem a falha local do `root`.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-linux-ext/brute-force-legacy/`](forense-linux-ext/brute-force-legacy/writeup.md)

#### 08 · Operation Brute force Legacy: o Retorno
* **Artefato:** `server.img` (o mesmo do desafio anterior).
* **Vetor:** Rootkit (`rk.tar`) com `install.sh` que insere uma regra `iptables` de saída (T1562.004).
* **Metodologia:** Análise dos arquivos deixados em `/tmp`, leitura de `vars.sh` e `install.sh` e separação da porta do backdoor da porta bloqueada.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-linux-ext/brute-force-legacy-retorno/`](forense-linux-ext/brute-force-legacy-retorno/writeup.md)

#### 12 · Hash Trace
* **Artefato:** `tsk.dd` (MBR com três partições ext2).
* **Vetor:** Arquivo identificado pelo conteúdo (MD5), e não pelo nome.
* **Metodologia:** `mmls`, `tsk_recover -e`, `md5sum` em lote e `fls`/`istat` para obter o inode.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-linux-ext/hash-trace/`](forense-linux-ext/hash-trace/writeup.md)

### 🗂️ 3.4 Forense de Disco Windows (NTFS)

#### 09 · Bash Twist
* **Artefato:** `Windows10.raw` (NTFS no setor 128).
* **Vetor:** Jump Lists em `AutomaticDestinations`, com o AppID identificando o programa.
* **Metodologia:** `fls` e `icat` para extrair as listas, `scripts/jl_min.py` para ler o `DestList` e conferência do AppID e do contador de acessos.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-windows-ntfs/bash-twist/`](forense-windows-ntfs/bash-twist/writeup.md)

#### 10 · Hidden Trace
* **Artefato:** `Windows10.raw`.
* **Vetor:** Timestomping (T1070.006) em `/root/passwords.txt`.
* **Metodologia:** Comparação de `$STANDARD_INFORMATION` e `$FILE_NAME` com `istat`, fração de segundo zerada e data anterior ao volume, com conversão explícita de UTC para UTC-3.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-windows-ntfs/hidden-trace/`](forense-windows-ntfs/hidden-trace/writeup.md)

#### 11 · First Click
* **Artefato:** `Windows10.raw`.
* **Vetor:** Histórico do Edge recuperado da Jump List, sem o banco de histórico na imagem.
* **Metodologia:** Leitura do `DestList` da Jump List do Edge e escolha do item mais antigo, confirmada por busca de URLs na imagem.
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-windows-ntfs/first-click/`](forense-windows-ntfs/first-click/writeup.md)

### 💽 3.5 Imagem Lógica AD1 (FTK Imager)

#### 14 · Operation Gerônimo
* **Artefato:** `hack.ad1` (Kali Linux, partição ext4).
* **Vetor:** Registros de acesso do Apache em uma imagem lógica.
* **Metodologia:** Leitura da árvore do AD1 (`scripts/ad1_min.py`), conferência de tamanho e MD5 dos logs do Apache e checagem de outras fontes (syslog, Firefox e `.bash_history`).
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-imagem-ad1/operation-geronimo/`](forense-imagem-ad1/operation-geronimo/writeup.md)

#### 15 · Hidden Checklist
* **Artefato:** `hack.ad1` (o mesmo do desafio anterior).
* **Vetor:** Arquivo de texto na área de trabalho do `root`, com autoria ligada ao hostname `KarenHacker` nos logs.
* **Metodologia:** Busca por nomes de arquivo na árvore do AD1, leitura do conteúdo e confirmação da autoria e do contexto (histórico do Metasploit e do shell).
* **Flag Extraída:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*
* **Write-up completo:** [`forense-imagem-ad1/hidden-checklist/`](forense-imagem-ad1/hidden-checklist/writeup.md)

---

## 📋 4. Resumo de Flags (Status de Resolução)

| # | Nome do Desafio | Categoria Principal | Artefato | Flag Recuperada | Status |
| :-: | :--- | :--- | :--- | :--- | :-: |
| 01 | Shadow Wire | Logs Sysmon (C2) | `c2.evtx` | 🔒 *oculta* | ✅ |
| 02 | Black Tide | Logs Sysmon (T1105) | `c2_1.evtx` | 🔒 *oculta* | ✅ |
| 03 | Silent Mail | Memória (e-mail) | `email.mem` | 🔒 *oculta* | ✅ |
| 04 | Operation Ghost Letter | Memória (linha do tempo) | `email.mem` | 🔒 *oculta* | ✅ |
| 05 | Deep Memory | Memória (Volatility) | `desafio.mem` | 🔒 *oculta* | ✅ |
| 06 | Print Strike | Memória (log `.evt`) | `win.mem` | 🔒 *oculta* | ✅ |
| 07 | Brute force Legacy | Linux ext3 (SSH) | `server.img` | 🔒 *oculta* | ✅ |
| 08 | Operation Brute force Legacy o Retorno | Linux ext3 (rootkit) | `server.img` | 🔒 *oculta* | ✅ |
| 09 | Bash Twist | NTFS (Jump Lists) | `Windows10.raw` | 🔒 *oculta* | ✅ |
| 10 | Hidden Trace | NTFS (timestomping) | `Windows10.raw` | 🔒 *oculta* | ✅ |
| 11 | First Click | NTFS (Edge) | `Windows10.raw` | 🔒 *oculta* | ✅ |
| 12 | Hash Trace | ext2 (hash e inode) | `tsk.dd` | 🔒 *oculta* | ✅ |
| 13 | Operação DFIR | Logs Sysmon (RDP) | `log.evtx` | 🔒 *oculta* | ✅ |
| 14 | Operation Gerônimo | AD1 (Apache) | `hack.ad1` | 🔒 *oculta* | ✅ |
| 15 | Hidden Checklist | AD1 (arquivos do usuário) | `hack.ad1` | 🔒 *oculta* | ✅ |

---

## 📁 5. Estrutura do Repositório

```text
.
├── forense-sysmon-evtx/
│   ├── shadow-wire/writeup.md
│   ├── black-tide/writeup.md
│   └── operacao-dfir/writeup.md
├── forense-de-memoria/
│   ├── silent-mail/writeup.md
│   ├── operation-ghost-letter/writeup.md
│   ├── deep-memory/writeup.md
│   └── print-strike/writeup.md
├── forense-linux-ext/
│   ├── brute-force-legacy/writeup.md
│   ├── brute-force-legacy-retorno/writeup.md
│   └── hash-trace/writeup.md
├── forense-windows-ntfs/
│   ├── bash-twist/writeup.md
│   ├── hidden-trace/writeup.md
│   └── first-click/writeup.md
├── forense-imagem-ad1/
│   ├── operation-geronimo/writeup.md
│   └── hidden-checklist/writeup.md
├── scripts/
│   ├── jl_min.py      # leitor de Jump List (DestList)
│   ├── evt_mini.py    # recuperação de registros .evt por assinatura LfLe
│   └── ad1_min.py     # leitor somente leitura de imagem AD1
└── README.md
```

---

## ⚖️ 6. Nota sobre o material

Material educacional. Os artefatos pertencem ao laboratório da plataforma Wargames e não estão incluídos neste repositório. Os scripts da pasta `scripts/` são leitores somente leitura, escritos para este CTF; use-os apenas em evidências sobre as quais você tem autorização.