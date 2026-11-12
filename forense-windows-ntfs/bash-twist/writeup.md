# 🌀 Bash Twist

**Categoria:** Forense de Disco Windows (NTFS) e artefatos de atividade do usuário
**Técnica:** Análise de Jump Lists (`AutomaticDestinations`, fluxo `DestList`)
**Artefato:** `Windows10.raw` (volume NTFS no setor 128)
**Flag:** 🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Contexto

O desafio pede o **nome do programa** que abriu repetidamente um arquivo chamado "bash" em uma estação Windows 10 e o **número total de aberturas**.

As Jump Lists são listas de itens recentes mantidas por aplicativo, em `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations`, em arquivos `<AppID>.automaticDestinations-ms`. O **AppID** é um identificador de 16 dígitos hexadecimais calculado a partir do caminho do executável. Cada arquivo é um contêiner OLE (Compound File) com um fluxo por item (um atalho LNK) e um fluxo `DestList`, que guarda caminho, data da última modificação e **contador de acessos** de cada item. Por registrarem o que cada programa abriu e quantas vezes, as Jump Lists são uma fonte clássica de evidência de atividade do usuário.

## Metodologia

1. **Integridade e estrutura:** SHA-256 da imagem (53.477.376 bytes) e tabela de partições (`mmls`): uma única partição NTFS, a partir do setor 128.
2. **Listagem:** `fls` mostra o perfil `C:\Users\Uroushsky` e, em `AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`, sete arquivos de Jump List.
3. **Extração:** `icat` extrai cada arquivo pelo número do registro MFT, e o `scripts/jl_min.py` abre o Compound File e lê o `DestList`.
4. **Localização do arquivo:** dois arquivos de Jump List citam o mesmo item, `C:\Users\User\Desktop\bash.txt`: `5f7b5f1e01b83767` (Quick Access) e `9b9cdc69c1c24e2b`, ambos com última modificação em 24/04/2025.
5. **Identificação do programa:** o AppID `9b9cdc69c1c24e2b` corresponde, nas tabelas públicas de AppIDs, a `██████`. O Quick Access é o histórico do Explorador de Arquivos, e não o programa que abriu o arquivo.
6. **Contador:** o campo de acessos do `DestList` vale `██████` na Jump List do programa e um valor menor no Quick Access, de forma consistente nos três campos em que o contador aparece (ponto flutuante no cabeçalho e na entrada, inteiro no deslocamento 116).

### Execução

```bash
sha256sum Windows10.raw
mmls Windows10.raw
fls -o 128 -r Windows10.raw | grep -i AutomaticDestinations
icat -o 128 Windows10.raw 83 > 9b9cdc69c1c24e2b.automaticDestinations-ms
python3 -I scripts/jl_min.py 9b9cdc69c1c24e2b.automaticDestinations-ms
```

## Evidências

* **Arquivo aberto:** `C:\Users\User\Desktop\bash.txt`
* **Jump List:** `9b9cdc69c1c24e2b.automaticDestinations-ms` (registro MFT 83)
* **Programa:** `██████`
* **Aberturas:** `██████`

## Flag

🔒 *oculta até o encerramento do CTF (13/11/2026, 23h59)*

## Lição aprendida

Quando mais de uma Jump List cita o mesmo arquivo, o **AppID** diz qual programa o abriu. Confira sempre a fonte pública que traduz o AppID, e não confunda o histórico do Explorador (Quick Access) com o do aplicativo.
