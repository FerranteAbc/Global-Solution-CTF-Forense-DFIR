# 🎯 Operation Gerônimo

**Categoria:** Forense de Imagem Lógica (AD1 / FTK Imager) e logs do Apache
**Técnica:** Leitura da árvore do AD1 e verificação dos registros de acesso do Apache
**Artefato:** `hack.ad1` (87.719.990 bytes)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O desafio pede a **quantidade de vezes que o servidor web Apache foi acessado** em um servidor Linux, a partir do artefato `hack.ad1`.

O AD1 (AccessData Custom Content Image) é uma imagem **lógica** criada pelo FTK Imager: guarda só os arquivos e pastas selecionados, e não o disco inteiro. Os dados ficam em blocos comprimidos com zlib, e cada arquivo carrega metadados como hashes MD5 e SHA-1 e datas. O Apache registra cada requisição em `/var/log/apache2/access.log` (Debian e derivados, como o Kali), uma linha por requisição, além do `error.log` e do `other_vhosts_access.log`. Por isso, contar as linhas desses registros é a forma direta de medir os acessos.

## Metodologia

1. **Contêiner:** o arquivo começa com a assinatura `ADSEGMENTEDFILE` e tem o cabeçalho `ADLOGICALIMAGE` no deslocamento `0x200`. A origem registrada é uma partição ext4 de um Kali Linux (kernel 4.13.0-kali1).
2. **Árvore de arquivos:** a estrutura foi lida em modo somente leitura (`scripts/ad1_min.py`) e tem 2.039 itens, incluindo o perfil de `root`, o `/boot` e o `/var/log`.
3. **Registros do Apache:** em `/var/log/apache2` estão `access.log`, `error.log` e `other_vhosts_access.log`. Foram verificados o tamanho e o hash MD5 de cada um: `██████`, MD5 `██████`.
4. **Outros rastros:** foram conferidos os demais registros coletados (`syslog`, `auth.log`, `kern.log`, `daemon.log` e rotações), o histórico do Firefox (`places.sqlite`, 30 endereços) e o `.bash_history` do `root`, em busca de menções a `apache`, `localhost` e `127.0.0.1`. Resultado: `██████`.
5. **Conclusão:** a quantidade de acessos ao Apache é `██████`.

### Execução

```bash
sha256sum hack.ad1 && head -c 15 hack.ad1; echo
python3 -I scripts/ad1_min.py hack.ad1 list | grep -i -E 'apache2|nginx'
# o nó raiz do AD1 se chama [root], então os caminhos começam em /[root]/
python3 -I scripts/ad1_min.py hack.ad1 cat /[root]/var/log/apache2/access.log | wc -c
python3 -I scripts/ad1_min.py hack.ad1 list | grep -i -E 'syslog|auth.log|bash_history|places.sqlite'
```

## Evidências

* **Artefato:** `hack.ad1`, SHA-256 `130d91294aaa402a7a8770e5b81aabc76cb333019cf07a795b91cb9d4f72fe5b`
* **Registros do Apache:** `access.log`, `error.log` e `other_vhosts_access.log` (tamanho `██████`, MD5 `██████`)
* **Outras fontes conferidas:** logs do sistema, histórico do Firefox e `.bash_history`
* **Acessos ao Apache:** `██████`

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

Uma imagem lógica só tem o que o coletor escolheu, então um resultado de um único arquivo precisa de uma segunda fonte para ser confiável. Aqui, além do tamanho e do hash dos registros do Apache, foram checados os logs do sistema, o navegador e o histórico do shell para corroborar o resultado.
