# 🕸️ Shadow Wire

**Categoria:** Forense de Logs do Windows (Sysmon / EVTX)
**Técnica:** Correlação de eventos Sysmon (ID 1, 3 e 22) com `Get-WinEvent`
**Artefato:** `c2.evtx` (386 eventos)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O desafio entrega o log do Sysmon de uma estação corporativa suspeita de infecção e pede o processo que se comunica com o servidor de Comando e Controle (C2) e o endereço desse servidor. O C2 é a infraestrutura com que o atacante controla o host comprometido; do lado da vítima, ele deixa rastros como consultas DNS e conexões de rede originadas por processos suspeitos.

Eventos do canal `Microsoft-Windows-Sysmon/Operational` usados na análise:

* **Event ID 1** (Process Create): imagem, linha de comando, hashes e processo pai.
* **Event ID 3** (Network Connection): IP e porta de origem e de destino.
* **Event ID 22** (DNS Query): nome consultado, resultado e processo que consultou.

## Metodologia

1. **Triagem no Visualizador de Eventos:** o log (386 eventos) tem 3 conexões de rede, 42 consultas DNS e 183 criações de processo. O Visualizador não traz o manifesto do Sysmon e mostra os campos sem rótulo, o que motivou a extração pelo PowerShell.
2. **Event ID 3:** duas conexões são do OneDrive (porta 443). A terceira, de um executável na área de trabalho do usuário `IEUser`, vai para a porta `4444` (muito usada por listeners do Metasploit) de um IP interno. É o Event Record ID 3992.
3. **Event ID 22:** o nome ██████ resolve para ██████ em consultas do Edge e do `smartscreen.exe` (3989 e 3990). O próprio executável consulta o IP literal (4001).
4. **Event ID 1 (3991):** o processo `██████` foi iniciado pelo `explorer.exe` e traz `OriginalFileName = ab.exe` (ApacheBench), incompatível com o nome do arquivo. Isso indica mascaramento (MITRE ATT&CK T1036).
5. **Pós-conexão (3993 a 3997):** um `cmd.exe` filho executa `net user` e `net user /domain`, descoberta de contas (T1087) típica de uma sessão de shell remoto.
6. **Conclusão:** o implante é o executável `██████` e o servidor C2 é o host `██████`, porta 4444.

### Execução

```powershell
# Troque o EventID (1, 3 ou 22) para ver cada tipo de evento
Get-WinEvent -Path .\c2.evtx -FilterXPath "*[System[EventID=3]]" | ForEach-Object {
    $x = [xml]$_.ToXml()
    "RecordId: $($_.RecordId)"
    $x.Event.EventData.Data | Format-List Name, '#text'
}
```

## Evidências

| Evento | Record ID | O que mostra |
| :-- | :-: | :-- |
| ID 22 | 3989, 3990 | `██████` resolvendo para `██████` |
| ID 1 | 3991 | `██████` com `OriginalFileName = ab.exe` |
| ID 3 | 3992 | Conexão TCP do executável para o IP, porta 4444 |
| ID 1 | 3993 a 3997 | `cmd.exe` filho com `net user` e `net user /domain` |

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

O mesmo IP aparece em três tipos de evento (DNS, criação de processo e conexão de rede). Correlacionar por Record ID e por ordem de tempo transforma eventos soltos em uma narrativa do incidente. E, sem o manifesto do Sysmon instalado, o Visualizador de Eventos não rotula os campos: ler o XML com `Get-WinEvent` resolve.
