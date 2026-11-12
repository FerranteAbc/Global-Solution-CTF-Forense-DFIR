# 🔗 Hash Trace

**Categoria:** Forense de Disco Linux (ext2) e identificação por hash
**Técnica:** Cálculo de MD5 dos arquivos recuperados com The Sleuth Kit e busca do inode
**Artefato:** `tsk.dd` (345.830.400 bytes)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O desafio pede o **número do inode** do arquivo cujo hash MD5 é `723937e41c361f3db69fbd0ae4afde13`, dentro de uma imagem de disco.

Uma função de hash gera um resumo de tamanho fixo a partir do conteúdo do arquivo. Na perícia, o hash serve para verificar a integridade de evidências e para identificar arquivos conhecidos. Em sistemas de arquivos Unix, como o ext2, o **inode** guarda os metadados do arquivo (dono, permissões, datas e ponteiros para os blocos), e o nome fica no diretório, que só associa o nome ao número do inode. Para achar um arquivo pelo conteúdo é preciso calcular o hash dos arquivos e, depois, descobrir o inode do arquivo encontrado. O The Sleuth Kit oferece `mmls` (partições), `fls` (listagem com inodes), `icat` (conteúdo pelo inode) e `istat` (metadados do inode).

## Metodologia

1. **Integridade:** SHA-256 da imagem antes da análise.
2. **Partições:** `mmls` mostra uma tabela MBR com quatro partições: três Linux (tipo 0x83), a partir dos setores 57, 10260 e 178695, e uma de swap (0x82). As três Linux são ext2.
3. **Extração:** `tsk_recover -e` extrai os arquivos de cada partição (alocados e não alocados) para uma pasta de trabalho, sem alterar a imagem. Foram 14 arquivos na partição 1, 1.554 na 2 e 11.868 na 4.
4. **Hashes:** o MD5 de todos os arquivos extraídos foi comparado com o valor do enunciado. Houve **uma única correspondência**: o `chain.b` da partição 1 (setor 57), com 612 bytes, o carregador de cadeia (chain loader) do LILO, instalado em `/boot`.
5. **Inode:** o `fls` na partição 1 associa o `chain.b` ao inode `██████`, e o `istat` confirma arquivo alocado, dono `root`, permissão `rw-r--r--` e tamanho de 612 bytes.

### Execução

```bash
sha256sum tsk.dd
mmls tsk.dd
tsk_recover -e -o 57 tsk.dd p1/
find p1 -type f -exec md5sum {} + | grep 723937e41c361f3db69fbd0ae4afde13
fls -o 57 tsk.dd | grep chain.b          # r/r ██████:  chain.b
istat -o 57 tsk.dd ██████
```

## Evidências

* **Partição:** 1, ext2, setor inicial 57 (`/boot`)
* **Arquivo:** `chain.b` (612 bytes)
* **MD5:** `723937e41c361f3db69fbd0ae4afde13`
* **Inode:** `██████`

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

O nome do arquivo não é a identidade dele: o hash identifica pelo conteúdo, e o inode liga o conteúdo aos metadados. Para varrer uma imagem inteira, extraia com `tsk_recover` e calcule os hashes em lote, sem montar nem alterar a evidência.
