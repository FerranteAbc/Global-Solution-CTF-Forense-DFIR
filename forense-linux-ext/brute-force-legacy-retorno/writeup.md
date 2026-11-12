# 🪝 Operation Brute force Legacy: o Retorno

**Categoria:** Forense de Disco Linux (ext3) e análise de rootkit
**Técnica:** Leitura de `install.sh` em artefatos do atacante (MITRE ATT&CK T1562.004)
**Artefato:** `server.img` (o mesmo do desafio anterior)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O desafio continua a investigação do servidor Debian `victoria` e pede a **porta que o atacante tentou bloquear no firewall** depois de obter acesso. Depois de comprometer um host, é comum instalar um rootkit para manter persistência e esconder a atividade.

No Linux, o firewall em nível de kernel (Netfilter) é configurado pelo `iptables`, e uma regra com a ação `DROP` descarta os pacotes que combinam com ela. Uma regra de saída (`-I OUTPUT`) para uma porta específica impede o servidor de se conectar a ela, por exemplo para barrar ferramentas de detecção ou serviços de resposta. A técnica é a T1562.004 (Impair Defenses: Disable or Modify System Firewall). A evidência costuma estar em scripts de instalação, no histórico de comandos e em arquivos temporários, como o `/tmp`.

## Metodologia

1. **Reaproveitamento:** a mesma imagem `server.img` (ext3, Debian 5.0.7), sempre em modo somente leitura.
2. **Artefatos do atacante:** a listagem de `/tmp` mostra dois arquivos fora do padrão: `c.pl` (1.063 bytes) e `rk.tar` (4.421.289 bytes).
3. **`c.pl`:** script Perl que abre um shell reverso para o IP e a porta recebidos como argumento e grava um programa compilado e marcado com setuid root por meio de uma configuração maliciosa do `exim`. É a escalada de privilégios usada contra o serviço de e-mail `exim4`.
4. **`rk.tar`:** na verdade um `tar.gz` com o diretório `rk/`, que contém binários trojanizados do `procps` (`ps`, `top`, `w` e outros), o servidor SSH `dropbear`, o utilitário `mig`, o `vars.sh` e o `install.sh`.
5. **`vars.sh`:** define `rk_port=44965` (porta do `dropbear`, o backdoor SSH) e `rk_home_dir=/usr/include/sslv3` (diretório escondido).
6. **`install.sh`:** copia o `dropbear` para o diretório escondido, aplica `chattr +ia`, cria persistência em `/etc/init.d/xfs3` e troca os binários do `procps`. Em quatro pontos ele executa ou grava uma regra `iptables -I OUTPUT 1 -p tcp --dport ██████ -j DROP`.
7. **Conclusão:** a porta que o atacante tentou bloquear é a `██████/TCP`, diferente da porta do backdoor (44965).

### Execução

```bash
ls -la /mnt/server/tmp
sha256sum /mnt/server/tmp/rk.tar /mnt/server/tmp/c.pl
mkdir -p /tmp/rk_analise && tar -xzf /mnt/server/tmp/rk.tar -C /tmp/rk_analise   # fora da evidência
tar -tzvf /mnt/server/tmp/rk.tar | head
cat /tmp/rk_analise/rk/vars.sh
grep -n iptables /tmp/rk_analise/rk/install.sh
```

## Evidências

* **`rk.tar`:** SHA-256 `6a324fcebd39bee3df601a2c0bae779d4238f227c025bef29ca33382ddbcd665`
* **`c.pl`:** SHA-256 `1648df3f1e0c032b757b6d68e1d34105e500bcab5986227ff917ec7d22a97e01`
* **Regra de firewall:** `iptables -I OUTPUT 1 -p tcp --dport ██████ -j DROP` (quatro linhas do `install.sh`)
* **Porta do backdoor (não é a resposta):** 44965

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

A resposta veio só do disco: nem o dump de memória foi necessário. Ao ler um script de instalação de rootkit, separe as portas por função (aqui, a do backdoor e a que o atacante quer bloquear) para não responder com a porta errada.
