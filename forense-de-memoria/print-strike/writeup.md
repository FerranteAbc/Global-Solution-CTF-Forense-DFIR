# 🖨️ Print Strike

**Categoria:** Forense de Memória (RAM) e logs `.evt` do Windows XP
**Técnica:** Recuperação de registros `.evt` por assinatura `LfLe` e conversão de fuso
**Artefato:** `win.mem` (256 MiB), obtido de `win.mem.7z`
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

Uma estação de trabalho comprometida teve um software de gerenciamento de impressão usado de forma suspeita. A tarefa é achar a **data e a hora em que ele foi acionado pela primeira vez**, no formato `FIAP{dd/mm/yyyy_hh:mm:ss}`.

Em máquinas virtuais VMware, a impressão virtual é feita pelo **ThinPrint**, instalado com o VMware Tools (`TPAutoConnSvc.exe`, `TPAutoConnect.exe`, `TPVCGateway.exe`). Ele grava eventos em um log próprio, o `ThinPrint.evt`. No Windows XP os logs usam o formato binário `.evt`: cada registro começa com a assinatura `LfLe` e guarda número do registro, `TimeGenerated`, `TimeWritten`, ID do evento, origem e mensagem. Os instantes são segundos desde 01/01/1970 em **UTC**. Como a memória guarda cópias desses arquivos, os registros podem ser recuperados do dump pela assinatura (o Volatility 2 tem o plugin `evtlogs` para isso).

## Metodologia

1. **Extração:** `7z x win.mem.7z` gera `win.mem` (268.435.456 bytes).
2. **Sistema:** `windows.info` identifica um Windows XP Professional SP3 de 32 bits (build 2600), máquina `LUCIANO-4A69E49`.
3. **Processos:** `windows.pslist` mostra 30 processos típicos, mais o `notepad.exe` e duas instâncias do FTK Imager (usado na aquisição). O único processo de impressão é o `spoolsv.exe`, um serviço padrão iniciado no boot, sem relação com o software procurado. Foi preciso procurar o software em outros artefatos.
4. **Busca na memória:** `strings -a win.mem | grep -i thinprint` mostra os componentes do ThinPrint e a referência a `ThinPrint.evt` em `C:\WINDOWS\system32\config`. Eles não estavam em execução na captura, mas deixaram registros.
5. **Recuperação dos registros:** a busca pela assinatura `LfLe` (script em Python, equivalente ao `evtlogs`) recupera três registros do evento 4002 ("Virtual channel initialized"), com origem `ThinPrint AutoConnect`, além de um registro do serviço `TPAutoConnSvc` ("TPAutoConnect Service started") alguns segundos antes.
6. **Primeiro acionamento:** o registro 1 do log do ThinPrint, em `██████`.
7. **Conversão para o horário local:** os instantes do `.evt` estão em UTC. Em Brasília (UTC-3), o primeiro acionamento foi em `██████`. A conversão foi conferida no terminal e reescrita no formato pedido.

### Execução

```bash
7z x win.mem.7z
vol -f win.mem windows.info
vol -f win.mem windows.pslist
strings -a win.mem | grep -i thinprint | sort -u | head
python3 -I scripts/evt_mini.py win.mem ThinPrint           # registros .evt por assinatura LfLe
TZ=America/Sao_Paulo date -d '██████ UTC' '+%d/%m/%Y_%H:%M:%S'
```

## Evidências

* **Software:** ThinPrint AutoConnect (VMware Tools), log `ThinPrint.evt`
* **Registros recuperados:** 3 do evento 4002 (números 1, 2 e 3), offsets 80855088, 80855916 e 80856744 no dump
* **Primeiro evento (UTC):** `██████`
* **Primeiro evento (Brasília, UTC-3):** `██████`

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

Logs `.evt` guardam o tempo em UTC (Unix epoch), e a plataforma esperava o horário local. Registre sempre o fuso de cada valor e faça a conversão de forma explícita. Outra lição: um processo que "não está rodando" ainda pode ter deixado registros na memória.
