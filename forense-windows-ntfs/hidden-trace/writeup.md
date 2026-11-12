# 🕵️ Hidden Trace

**Categoria:** Forense de Disco Windows (NTFS) e linha do tempo
**Técnica:** Detecção de timestomping comparando `$STANDARD_INFORMATION` e `$FILE_NAME` (MITRE ATT&CK T1070.006)
**Artefato:** `Windows10.raw` (o mesmo do desafio Bash Twist)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O desafio pede a **data e a hora reais de criação** do arquivo `passwords.txt`, cujos metadados foram manipulados.

No NTFS, cada arquivo é descrito por um registro da `$MFT` com dois conjuntos de quatro carimbos de tempo (criação, modificação, alteração do registro MFT e último acesso): o atributo `$STANDARD_INFORMATION` (`$SI`) e o `$FILE_NAME` (`$FN`). O `$SI` é o que o Explorer e as APIs comuns mostram e **pode ser alterado por programas de usuário**, o timestomping, usado para esconder a data real. O `$FN` é mantido só pelo kernel e não é alterado pelas ferramentas comuns. Divergência entre os dois e **fração de segundo igual a zero** no `$SI` indicam adulteração, e a data real costuma ser a do `$FN`.

## Metodologia

1. **Localização:** a `$MFT` foi listada com `fls`, e o `passwords.txt` é o registro MFT **60**, em `/root/passwords.txt`, com tamanho zero.
2. **Comparação dos carimbos (`istat`):** o `$SI` mostra criação, modificação e acesso em 23/04/2020 às `██████` com fração zerada (típico de timestomping), e o `$FN` mostra os quatro carimbos em outro dia, com fração de segundo preenchida.
3. **Interpretação:** a data de 2020 do `$SI` é **anterior à própria criação do volume** (a `$MFT` foi criada em 2024), o que é impossível para uma data real. Os carimbos do `$FN` são coerentes com a alteração do registro MFT, que marca o momento em que a adulteração foi feita. A criação real é o valor do `$FN`.
4. **Fuso:** o NTFS grava em UTC. O `$FN` marca `██████`; no horário de Brasília (UTC-3), o fuso do ambiente de análise, a criação real foi às `██████`.

### Execução

```bash
fls -o 128 -r Windows10.raw | grep -i passwords.txt
istat -o 128 -z UTC Windows10.raw 60      # carimbos em UTC
istat -o 128 Windows10.raw 60             # horário local da máquina de análise
```

## Evidências

* **Arquivo:** `/root/passwords.txt` (registro MFT 60, 0 bytes)
* **`$STANDARD_INFORMATION` (adulterado):** criação em 23/04/2020 `██████`
* **`$FILE_NAME` (real):** criação em `██████` UTC, ou `██████` em Brasília
* **Alteração do registro MFT:** posterior à criação real, pouco depois (`██████` UTC)

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

O `$SI` mente, o `$FN` costuma dizer a verdade. Sempre compare os dois conjuntos de carimbos e desconfie de frações de segundo zeradas e de datas anteriores à criação do volume. E converta o fuso de forma explícita: o NTFS guarda UTC, e a flag foi pedida no horário local.
