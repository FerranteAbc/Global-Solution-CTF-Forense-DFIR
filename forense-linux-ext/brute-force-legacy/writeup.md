# 🔨 Brute force Legacy

**Categoria:** Forense de Disco Linux (ext3) e logs de autenticação
**Técnica:** Análise do `auth.log` para caracterizar força bruta SSH
**Artefato:** `server.img` (ext3, Debian 5.0.7, host `victoria`)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O desafio entrega três artefatos de um servidor Debian antigo (imagem de disco, dump de memória e arquivos de configuração e logs) e descreve um possível ataque de força bruta. Esta etapa pede a **conta que gerou o alerta** e o **número de alertas de login malsucedido** dela, no formato `FIAP{conta_qtd}`.

Na força bruta contra SSH, o atacante tenta muitas combinações de usuário e senha. No Debian, o rastro fica em `/var/log/auth.log`, onde o `sshd` e o PAM gravam `Failed password for ... from <IP>`, `Invalid user <nome> from <IP>` e `authentication failure`. Contar as ocorrências por conta e por IP de origem caracteriza o ataque. Outros arquivos corroboram: `faillog`, `btmp`, `wtmp` e `/etc/passwd`.

## Metodologia

1. **Preparação:** `server.img.zip` foi descompactado. O `file` identificou um ext3. Foi calculado o SHA-256 e a imagem foi montada **somente leitura e sem reproduzir o journal** (`-o ro,loop,noload`), para não alterar a evidência.
2. **Sistema:** `/etc/debian_version` (5.0.7) e `/etc/hostname` (`victoria`) indicam um Debian 5.0 (Lenny). O `/etc/passwd` lista contas do sistema e um usuário comum, `pepito`.
3. **Logs:** o `/var/log/auth.log` (105 linhas) concentra as falhas. Uma falha local isolada de `root` no `tty1` (`FAILED LOGIN (1)`) não tem relação com o ataque.
4. **Ataque:** em 06/02, entre 15:16:20 e 15:21:10, o `sshd` registra tentativas repetidas contra o usuário `██████`, que não existe no sistema (`Invalid user`), todas do IP `192.168.56.1`, em várias conexões SSH distintas.
5. **Contagem:** para essa conta há eventos `Failed none` (tentativa sem senha) e `Failed password`, todos do mesmo IP, num total de `██████` alertas de login malsucedido. A falha local de `root` foi descartada.
6. **O ataque funcionou?** Não há nenhuma linha `Accepted password` ou `Accepted publickey` no período, e o `faillog` registra falha apenas para o `root`.

### Execução

```bash
unzip server.img.zip && sha256sum server.img && file server.img
sudo mount -o ro,loop,noload server.img /mnt/server

cat /mnt/server/etc/debian_version /mnt/server/etc/hostname
grep -E 'Invalid user|Failed (none|password)' /mnt/server/var/log/auth.log | head -30
grep -cE 'Failed (none|password)' /mnt/server/var/log/auth.log
grep -E 'Failed (none|password)' /mnt/server/var/log/auth.log \
  | awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' | sort | uniq -c   # por conta
grep -E 'Accepted' /mnt/server/var/log/auth.log                              # sem saída
```

## Evidências

* **Origem do ataque:** `192.168.56.1`, via SSH (porta 22)
* **Janela de tempo:** 06/02/2011, das 15:16:20 às 15:21:10
* **Conta alvo:** `██████` (usuário inexistente)
* **Alertas de login malsucedido:** `██████` (`Failed none` mais `Failed password`)
* **Login aceito:** nenhum

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

Contar só `Failed password` não bastou: o total de alertas inclui também os `Failed none`. Defina com clareza **o que** está sendo contado e descarte o que não pertence ao ataque (como a falha local do `root`). Montar a imagem com `ro,noload` preserva a evidência.
