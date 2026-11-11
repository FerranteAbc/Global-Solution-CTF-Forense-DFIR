# 🚨 Operação DFIR

**Categoria:** Forense de Logs do Windows (Sysmon / EVTX) e resposta a incidentes
**Técnica:** Contagem de eventos por ID, análise de força bruta RDP e localização de evento por horário (MITRE ATT&CK T1110 e T1021.001)
**Artefato:** `log.evtx` (60.887.040 bytes, 74.970 registros)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O aluno atua como analista de Resposta a Incidentes e Forense Digital (DFIR) para investigar um possível ataque a um servidor crítico. A missão tem duas partes: **totalizar os eventos com IDs 1 e 3** e **localizar o evento de 05/01/2021 às 23:35:52**, que traz o IP e a porta de origem. O formato é `FIAP{TOTALEVENTOS_IP_ORIGEM:PORTA_ORIGEM}`.

O Sysmon registra, no canal `Microsoft-Windows-Sysmon/Operational`, o Event ID 1 (Process Create) e o Event ID 3 (Network Connection), este com o campo `Initiated` (`true` quando a máquina inicia a conexão e `false` quando a recebe). O arquivo EVTX pode ser lido pelo Visualizador de Eventos e pelo PowerShell (`Get-WinEvent`). Um volume muito alto de conexões de entrada na porta 3389 (RDP) vindas de muitos endereços externos é o padrão típico de força bruta contra o RDP (T1110, com o RDP como serviço explorado, T1021.001).

## Metodologia

1. **Integridade:** SHA-256 do `log.evtx` com `Get-FileHash`. O cabeçalho indica 74.970 registros em 923 blocos (chunks).
2. **Contagem por ID:** `Get-WinEvent` com `-FilterXPath "*[System[EventID=1]]"` e `"*[System[EventID=3]]"` retorna `██████` eventos de ID 1 e `██████` de ID 3. O total é `██████`.
3. **Caracterização do tráfego:** todos os eventos de ID 3 têm `Initiated = false` (conexões **recebidas**) e quase todos têm como destino a porta 3389 do servidor `THM-SOC-DC01.thm.soc` (`10.10.98.207`, Windows Server 2019), pelo `svchost.exe` (serviço Remote Desktop). Elas partem de 205 endereços IP distintos, e o mais frequente é o `103.143.206.243`, com 20.697 conexões. O padrão é compatível com força bruta contra o RDP.
4. **Horário do enunciado:** o log cobre 06/01/2021 01:35 UTC a 09/01/2021 20:36 UTC. O evento mais antigo (`RecordId` 85723, `Get-WinEvent -Oldest -MaxEvents 1`) foi gravado às **01:35:52 UTC de 06/01/2021**, o que equivale a 23:35:52 de 05/01 em **UTC-2**, o fuso do enunciado. Na máquina de análise (UTC-3), o PowerShell mostra o mesmo evento às 22:35:52 de 05/01. É o único evento gravado nesse segundo.
5. **Campos do evento (`ToXml()`):** Event ID 3 (regra `RDP`), `Initiated = false`, TCP, processo `svchost.exe`, IP de origem `██████`, porta de origem `██████`, destino `10.10.98.207:3389`.
6. **Flag:** total de eventos, IP e porta de origem, no formato pedido.

### Execução

```powershell
Get-FileHash .\log.evtx -Algorithm SHA256
(Get-WinEvent -Path .\log.evtx -FilterXPath "*[System[EventID=1]]" | Measure-Object).Count
(Get-WinEvent -Path .\log.evtx -FilterXPath "*[System[EventID=3]]" | Measure-Object).Count

$e = Get-WinEvent -Path .\log.evtx -Oldest -MaxEvents 1
$e.RecordId; $e.TimeCreated.ToUniversalTime()
([xml]$e.ToXml()).Event.EventData.Data | Format-List Name, '#text'
```

## Evidências

* **Host monitorado:** `THM-SOC-DC01.thm.soc` (`10.10.98.207`)
* **Eventos ID 1 e ID 3:** `██████` e `██████`, total `██████`
* **Evento localizado:** `RecordId` 85723, ID 3 (RDP), 01:35:52 UTC de 06/01/2021
* **Origem:** `██████:██████`, destino `10.10.98.207:3389`

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

Horário é a maior fonte de erro em perícia. O log não tem nenhum evento às 23:35:52 de 05/01 em UTC: o enunciado usa UTC-2, e a máquina de análise, UTC-3. Antes de procurar por horário, descubra o fuso em que a pergunta foi escrita. Já a contagem por `-FilterXPath` evita carregar e filtrar 74 mil objetos na mão.
