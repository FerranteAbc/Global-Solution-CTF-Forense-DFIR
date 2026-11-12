# 👻 Operation Ghost Letter

**Categoria:** Forense de Memória (RAM) e linha do tempo
**Técnica:** Cabeçalho `Date` (RFC 5322), linha mbox `From -` e corroboração por registros do cliente
**Artefato:** `email.mem` (o mesmo do desafio Silent Mail)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

Mesmo cenário do Silent Mail. Agora a pergunta é a **data e o horário exatos do envio** do e-mail, no formato `FIAP{dd/mm/yyyy_hh:mm:ss}`.

Em um incidente, a linha do tempo é tão importante quanto identificar os envolvidos. O cabeçalho `Date` da RFC 5322 registra a criação da mensagem pelo cliente com o deslocamento de fuso (`-0300` para Brasília). Clientes baseados em mbox, como o Thunderbird, gravam também uma linha `From -` com o mesmo instante em UTC. O analista precisa saber qual fuso o enunciado espera e confirmar que as duas representações descrevem o mesmo instante.

## Metodologia

1. **Reaproveitamento:** o `email.mem` extraído no desafio anterior foi reutilizado.
2. **Cabeçalho `Date`:** a busca por datas no formato RFC 5322 retorna sete ocorrências idênticas, `██████`. As outras datas do dump (cabeçalhos HTTP em GMT) são de navegação, não da mensagem.
3. **Mensagem correta:** o contexto do cabeçalho (`grep -B5 -A5`) mostra, no mesmo bloco, `To`, `From`, `Subject` e `Message-ID`, o que liga a data ao e-mail investigado.
4. **Corroboração pela linha mbox:** antes e depois da mensagem aparece `██████` (quatro ocorrências). Como Brasília é UTC-3, as duas representações são o mesmo instante.
5. **Corroboração pelo cliente:** registros internos do Thunderbird com a marca `message-manager-close` ficam cerca de um segundo depois do carimbo `Date`, consistente com o envio.
6. **Escolha do fuso:** o enunciado não pede UTC. Foi adotado o horário local gravado no cabeçalho `Date` (-0300), e o UTC serviu apenas de corroboração.

### Execução

```bash
strings -a email.mem | grep -E '^Date: ' | sort | uniq -c | sort -nr | head
strings -a email.mem | grep -B5 -A5 -E '^Date: ██████'
strings -a email.mem | grep -E '^From - '
grep -a -b -o -E 'Date: ██████ [0-9:]+ -0300' email.mem   # offsets
```

## Evidências

* **Cabeçalho `Date`:** `██████`, sete ocorrências (offsets, por exemplo, 658303261, 721438669, 746488248, 817258936 e 1038891581)
* **Linha mbox `From -`:** `██████`, quatro ocorrências (offsets 746488096, 746489112, 817258784 e 817259800)
* **Mensagem vinculada:** `ana <ana@xyz.site>` para o destinatário do desafio anterior, assunto `Senha`

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

O mesmo instante pode aparecer em fusos diferentes no mesmo artefato. Antes de montar a resposta, confirme o fuso que o enunciado espera e corrobore o valor por um segundo artefato independente (aqui, a linha mbox e os registros do cliente).
