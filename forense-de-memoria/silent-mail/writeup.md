# 📧 Silent Mail

**Categoria:** Forense de Memória (RAM)
**Técnica:** Recuperação de e-mail em dump com `strings` e `grep` (cabeçalhos RFC 5322)
**Artefato:** `email.mem` (1 GiB), obtido de `email.mem.7z`
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

Ana, do setor financeiro, enviou um e-mail suspeito em colaboração com um insider de TI. O dump de memória da máquina dela foi coletado e a tarefa é descobrir o **destinatário** da mensagem.

Clientes como o Mozilla Thunderbird montam a mensagem inteira (cabeçalhos e corpo) em memória durante a composição e o envio. Por isso fragmentos do e-mail permanecem no dump em texto, mesmo sem a caixa de saída ou o servidor. Os cabeçalhos RFC 5322 (`From`, `To`, `Subject`, `Date`, `Message-ID`) são padronizados e podem ser localizados por `strings` combinado com `grep`, uma técnica simples e eficaz quando não há perfil de símbolos para uma análise estruturada.

## Metodologia

1. **Extração:** `7z x email.mem.7z` gera o dump bruto `email.mem` (1.073.741.824 bytes).
2. **Identificação da aplicação:** `strings -a` mostra muitos componentes do Mozilla Thunderbird (módulos `messengercompose`, `MsgComposeCommands.js`, `thunderbird.exe`, versão 115.18.0). O e-mail foi composto e enviado por esse cliente.
3. **Cabeçalhos:** a busca por `From`, `To`, `Subject` e `Date` retorna a mesma mensagem em sete regiões diferentes da memória.
4. **Reconstrução:** o contexto em volta do cabeçalho `To:` (`grep -B` e `-A`) mostra a mensagem completa: remetente `ana <ana@xyz.site>`, destinatário `██████`, assunto `Senha` e o `Message-ID`.
5. **Outros destinatários:** não há `Cc:` nem `Bcc:`. O único destinatário é o do cabeçalho `To:`.

### Execução

```bash
7z x email.mem.7z
strings -a email.mem | grep -i -E "thunderbird|messengercompose" | head
strings -a email.mem | grep -E "^(From|To|Subject|Date): " | sort | uniq -c | sort -nr | head
strings -a email.mem | grep -B6 -A6 "^To: "
```

## Evidências

* **Cliente:** Mozilla Thunderbird 115.18.0
* **Remetente:** `ana <ana@xyz.site>`
* **Destinatário:** `██████`
* **Assunto:** `Senha`
* **Localização:** a mensagem aparece em vários offsets (por exemplo, o cabeçalho `To:` no byte 658303376)

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

A memória guarda o que o disco não guarda. Mesmo sem Volatility, `strings` e `grep` com contexto recuperam uma mensagem inteira, e a repetição da mesma mensagem em várias regiões é um bom sinal de que o achado é real e não ruído.
