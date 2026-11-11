# 🌊 Black Tide

**Categoria:** Forense de Logs do Windows (Sysmon / EVTX)
**Técnica:** Linha do tempo DNS, processo e rede (MITRE ATT&CK T1105, Ingress Tool Transfer)
**Artefato:** `c2_1.evtx`
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

Um alerta interno apontou tráfego anômalo e a suspeita de que um software malicioso foi baixado clandestinamente em uma máquina da rede. A tarefa é achar o **domínio de origem do download** e o **IP do host infectado** no log do Sysmon.

Quando o atacante transfere a ferramenta para dentro do ambiente, o processo que baixa precisa resolver o nome do servidor. Esse passo deixa um vestígio de DNS (Event ID 22) antes da execução do artefato (Event ID 1) e da conexão de rede (Event ID 3).

## Metodologia

1. **Verificação do artefato:** o SHA-256 de `c2_1.evtx` é idêntico ao de `c2.evtx` (desafio Shadow Wire). É o mesmo log com outra pergunta, então a linha do tempo já levantada pode ser reaproveitada.
2. **Origem do download (Event ID 22):** entre os nomes consultados (domínios Microsoft, Akamai e de redes de anúncios), só um é resolvido para um endereço da rede interna: `██████`, que aponta para `██████`. As consultas partem do Edge e do `smartscreen.exe`, o componente que verifica a reputação de executáveis baixados.
3. **Linha do tempo (Record IDs 3989 a 3992):** o DNS do Edge (3989 e 3990) precede a criação do processo suspeito (3991), que em seguida abre uma conexão TCP para o mesmo IP na porta 4444 (3992). O Sysmon não registrou a gravação do arquivo baixado, então a origem do download é **inferida por correlação**, e não por um evento de arquivo.
4. **Host infectado (Event ID 3):** o evento 3992 informa `SourceIp = ██████` e `SourceHostname = MSEDGEWIN10.localdomain`. Uma consulta DNS do próprio host (Record ID 4125) resolve `MSEDGEWIN10` para esse mesmo IP, o que confirma o endereço.

### Execução

```powershell
Get-FileHash .\c2.evtx, .\c2_1.evtx -Algorithm SHA256

# Consultas DNS (ID 22) cujo resultado aponta para a rede interna
Get-WinEvent -Path .\c2_1.evtx -FilterXPath "*[System[EventID=22]]" | ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
        RecordId  = $_.RecordId
        Consulta  = ($d | Where-Object Name -eq 'QueryName').'#text'
        Resultado = ($d | Where-Object Name -eq 'QueryResults').'#text'
        Processo  = ($d | Where-Object Name -eq 'Image').'#text'
    }
} | Where-Object { $_.Resultado -match '192\.168\.' } | Format-Table -AutoSize
```

## Evidências

* **SHA-256 de `c2_1.evtx`:** `724b9c6df98de1a7dea77c61f2bad36c4c2b8a7c704efb523836a15f3b691eb5`
* **Domínio de origem (ID 22, 3989 e 3990):** `██████` → `██████`
* **Execução do artefato (ID 1, 3991) e conexão ao C2 (ID 3, 3992):** porta de destino 4444
* **Host infectado:** `MSEDGEWIN10.localdomain`, IP `██████`

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

Quando o Sysmon não registra a criação do arquivo baixado, a correlação temporal entre DNS, criação de processo e conexão de rede sustenta a conclusão. O relatório deve dizer que a origem foi inferida, e não observada diretamente.
