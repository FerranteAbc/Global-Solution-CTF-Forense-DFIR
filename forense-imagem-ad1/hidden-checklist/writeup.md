# 📝 Hidden Checklist

**Categoria:** Forense de Imagem Lógica (AD1 / FTK Imager) e arquivos de usuário
**Técnica:** Busca de documentos do usuário e atribuição de autoria pelo hostname dos logs
**Artefato:** `hack.ad1` (o mesmo do desafio Operation Gerônimo)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O desafio pede o **terceiro item de uma lista de tarefas** (checklist) criada por uma usuária chamada Karen, no mesmo `hack.ad1` do desafio anterior.

Em perícia de sistemas Linux, os arquivos pessoais do usuário, principalmente as pastas `Desktop` e `Documents`, costumam revelar intenções e planejamento. Arquivos de texto simples, mesmo sem extensão, podem ser lidos direto do conteúdo extraído da imagem lógica. A autoria pode vir do nome de usuário, do **hostname** registrado nos logs do sistema ou dos metadados do arquivo.

## Metodologia

1. **Listagem da árvore do AD1:** com a estrutura lida em modo somente leitura (2.039 itens), foi feita uma busca por nomes como `check`, `todo` e `lista`.
2. **Localização:** o único arquivo com esse perfil é `/root/Desktop/Checklist` (60 bytes, MD5 `050c06331d83aab64efad77ab7107dda`, SHA-1 `ae4158887757aa08667c787c6ef7bf12e9440d97`), na área de trabalho do `root`.
3. **Autoria:** as linhas do `/var/log/syslog` registram o hostname `KarenHacker`, o que associa a máquina, e a lista, à Karen.
4. **Conteúdo:** o arquivo é texto simples com o título `Check List:` e três itens: `Gain Bob's Trust`, `Learn how to hack` e `██████`.
5. **Contexto da investigação:** os itens são coerentes com os demais artefatos: o histórico do Metasploit (`~/.msf4/history`) cria um workspace chamado `Bob` e ataca o host `10.0.0.101`, e o `.bash_history` mostra a pasta `myfirsthack`.
6. **Conclusão:** o terceiro item da checklist é `██████`.

### Execução

```bash
python3 -I scripts/ad1_min.py hack.ad1 list | grep -i -E 'check|todo|lista'
python3 -I scripts/ad1_min.py hack.ad1 cat /[root]/root/Desktop/Checklist
python3 -I scripts/ad1_min.py hack.ad1 cat /[root]/var/log/syslog | head -5
```

## Evidências

* **Arquivo:** `/root/Desktop/Checklist` (60 bytes)
* **Autora (hostname nos logs):** `KarenHacker`
* **Conteúdo:** 1. Gain Bob's Trust; 2. Learn how to hack; 3. `██████`

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

A autoria de um arquivo não precisa estar nos metadados: o hostname nos logs do sistema liga a máquina à pessoa. E os artefatos de contexto (histórico do Metasploit e do shell) mostram que o conteúdo do arquivo bate com a atividade da máquina.
