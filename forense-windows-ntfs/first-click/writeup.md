# 🖱️ First Click

**Categoria:** Forense de Disco Windows (NTFS) e histórico de navegação
**Técnica:** Jump List do Microsoft Edge (`DestList`) quando o banco de histórico não está presente
**Artefato:** `Windows10.raw` (o mesmo dos desafios Bash Twist e Hidden Trace)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O desafio pede a **URL do primeiro site acessado** pelo usuário no Microsoft Edge. O histórico de navegação costuma ficar em um banco SQLite do perfil do navegador, mas outros artefatos do Windows também guardam endereços visitados.

A Jump List do Edge (`9d1f905ce5044aee.automaticDestinations-ms`) registra sites acessados ou fixados a partir do navegador. O fluxo `DestList` numera os itens **em ordem de inclusão** e guarda a data da última modificação de cada um. Como o identificador cresce a cada novo item, o de menor número é o mais antigo.

## Metodologia

1. **Busca por artefatos do Edge:** a listagem da `$MFT` mostra o perfil `Users\Uroushsky`, mas **não** a pasta do banco de histórico do Edge. A evidência de navegação está nas Jump Lists, em `AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`.
2. **Identificação:** o arquivo `9d1f905ce5044aee.automaticDestinations-ms` (registro MFT 84) contém URLs, o que o identifica como a lista do Edge.
3. **Leitura do `DestList`:** o fluxo tem dois itens. O item 1 é uma URL de `██████`, com 1 acesso, e o item 2 é uma busca no Bing sobre a chave de produto do Windows, com 2 acessos e data bem posterior.
4. **Confirmação:** uma busca por URLs na imagem inteira só retornou esses endereços (além de espaços de nomes XML), sem outro site visitado.
5. **Conclusão:** o primeiro site acessado, em ordem cronológica, é o do item 1: `██████`.

### Execução

```bash
fls -o 128 -r Windows10.raw | grep -i AutomaticDestinations
icat -o 128 Windows10.raw 84 > 9d1f905ce5044aee.automaticDestinations-ms
python3 -I scripts/jl_min.py 9d1f905ce5044aee.automaticDestinations-ms
strings -a Windows10.raw | grep -i -E 'https?://' | sort -u | head    # confirmação
```

## Evidências

* **Jump List do Edge:** `9d1f905ce5044aee.automaticDestinations-ms` (registro MFT 84)
* **Item 1 (o mais antigo):** `██████`
* **Item 2:** busca no Bing sobre a chave de produto do Windows

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

Quando o banco de histórico do navegador não está na imagem, as Jump Lists são um plano B. A ordem dos itens no `DestList` dá a ordem cronológica de inclusão, e a URL deve ser registrada **completa**, com o protocolo.
