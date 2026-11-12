# 🧠 Deep Memory

**Categoria:** Forense de Memória (RAM)
**Técnica:** Volatility 3 (`windows.info`, `windows.pslist`, `windows.envars`) e decodificação hexadecimal
**Artefato:** `desafio.mem` (256 MiB), obtido de `desafio.mem.7z`
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

A flag está escondida "profundamente" em um dump de memória, e o enunciado avisa que uma busca simples por `FLAG` não funciona: é preciso usar o Volatility.

O Volatility interpreta as estruturas internas do Windows na RAM. Cada processo é um `_EPROCESS` que aponta para o PEB (Process Environment Block), e o PEB referencia a linha de comando e o **bloco de variáveis de ambiente**. O plugin `envars` lê esse bloco e lista as variáveis de cada processo. Como o conteúdo é texto, um valor pode ficar codificado (por exemplo, em hexadecimal) para escapar de uma busca por `FIAP` ou `FLAG`. Decodificar é o último passo.

## Metodologia

1. **Extração:** `7z x desafio.mem.7z` gera `desafio.mem` (268.435.456 bytes).
2. **Sistema:** `windows.info` identifica um Windows XP Professional SP3 de 32 bits; as strings do dump confirmam a versão e o nome da máquina, `LUCIANO-4A69E49`.
3. **Processos:** `windows.pslist` mostra 25 processos, todos legítimos (`System`, `smss.exe`, `csrss.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, vários `svchost.exe`, `explorer.exe`, VMware Tools). Nada suspeito, então o dado oculto estaria em outro tipo de artefato.
4. **Ambiente dos processos:** `windows.envars` com `grep -i CHALLENGE` revela uma variável fora do padrão do Windows, com um valor em hexadecimal, no `explorer.exe` (PID 1532) e no `FTK Imager.exe` (PID 1124).
5. **Decodificação:** o valor é uma sequência de 17 bytes em hexadecimal. A conversão com `xxd -r -p` produz o texto no formato `FIAP{...}`, seguido de uma quebra de linha (byte `0a`).
6. **Verificação cruzada:** a mesma variável, com o mesmo valor, aparece em várias cópias do bloco de ambiente na memória (ASCII e UTF-16), sem variação, o que descarta corrupção.

### Execução

```bash
7z x desafio.mem.7z
vol -f desafio.mem windows.info          # ou: python3 vol.py -f desafio.mem windows.info
vol -f desafio.mem windows.pslist
vol -f desafio.mem windows.envars | grep -i CHALLENGE
echo '██████' | xxd -r -p
```

> Um `| head` antes do `grep` pode terminar em `BrokenPipeError`: o `head` fecha o pipe antes de o plugin terminar. Isso não afeta o resultado.

## Evidências

* **Sistema:** Windows XP Professional SP3, 32 bits, `LUCIANO-4A69E49`
* **Processos:** 25, nenhum suspeito
* **Local do dado:** variável de ambiente `CHALLENGE` do `explorer.exe` (PID 1532) e do `FTK Imager.exe` (PID 1124)
* **Valor bruto (hexadecimal):** `██████`
* **Valor decodificado:** `██████`

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

`strings | grep` não acha um valor codificado. Listar o **ambiente** dos processos é uma etapa barata que deve entrar em qualquer triagem de memória, porque malwares e scripts também passam parâmetros e segredos por variáveis de ambiente.
