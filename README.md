# NVG Hardening Scanner

Scanner CLI de auditoria passiva para NVG OS (nOS), baseado em Arch Linux. Usa Python
3.10+ e somente a biblioteca padrão em execução. Audita configuração e estado
local; não explora serviços, envia sondas, tenta autenticar, quebra senhas ou aplica
correções. Os comentários do código explicam a motivação de segurança dos checks.

O detector de exposição de chaves tem escopo **(b): auditoria do próprio usuário
no nOS**, e não busca genérica de segredos em qualquer máquina Arch. Desde a
primeira versão, exige habilitação explícita e limita a leitura a 256 KiB por
arquivo, 1 MiB por execução, oito arquivos e cinco segundos de análise por padrão.
Não há recursão. Somente históricos bash/zsh do usuário selecionado são propostos
no exemplo; `/tmp`, logs, outros usuários e clipboard não são incluídos por padrão.
Todos os campos de conteúdo ficam fora dos logs e do diff; nem fragmentos nem
hashes de segredos são persistidos. Chaves/mnemônicos confirmados e credenciais bunker são `critical`. Partes Shamir isoladas geram `warning/high`, sem reconstrução ou afirmação de exposição da seed.

## Execução rápida

No diretório do projeto, sem instalação nem acesso à internet:

```sh
PYTHONPATH=src python3 -m nvg_scanner --list-checks
PYTHONPATH=src python3 -m nvg_scanner \
  --config config/example.json --profile live --format markdown
```

Para a integração específica documentada do nOS, use `config/nos.json` e a seção **Integração nOS 0.3** abaixo. Para manter a política genérica anterior, copie e adapte o exemplo:

```sh
cp config/example.json config/local.json
```

Edite `config/local.json` para representar os usuários, UIDs, caminhos, unidades e
portas reais da distribuição. O usuário `nvg`, UID 1000 e os caminhos de carteiras
são **ilustrativos**, não uma descoberta ou uma convenção obrigatória. O arquivo
contém políticas e caminhos, nunca o conteúdo de chaves ou credenciais.

Para produzir os dois relatórios em um diretório novo:

```sh
PYTHONPATH=src python3 -m nvg_scanner \
  --config config/local.json --profile installed \
  --format both --output reports/primeira-auditoria
```

Isso cria `report.json` e `report.md`. Arquivos são criados com modo 0600 e não
sobrescrevem destinos existentes; o diretório final novo usa 0700. JSON e Markdown
representam **a mesma execução**, com o mesmo timestamp e score. Use outro destino
para auditorias posteriores. Saída em stdout/redirecionamento depende das
permissões e da umask do shell.

```sh
PYTHONPATH=src python3 -m nvg_scanner \
  --config config/local.json --checks network_checks tor_checks --format json
```

Não é necessário executar tudo como root. Sem acesso a `/etc/shadow`, por exemplo,
esse check gera `warning`. Para uma auditoria com maior acesso, a partir de uma
cópia confiável do projeto, é possível usar:

```sh
sudo env PYTHONPATH="$PWD/src" python3 -m nvg_scanner \
  --config "$PWD/config/local.json" --profile installed \
  --format both --output "$PWD/reports/auditoria-root"
```

O scanner não eleva privilégios automaticamente. Os checks de rede usam `ss`, do
pacote Arch `iproute2`; os de serviços usam `systemctl`, do `systemd`. Eles não são
instalados pelo scanner. Ferramenta ausente, systemd indisponível e falha de
permissão são resultados inconclusivos, não `pass`. Os comandos têm timeout
configurável e PATH fixo. Coletores genéricos não usam shell. O adaptador nOS usa Bash com uma expressão fixa e argumentos separados para chamar somente `network_verify` da biblioteca instalada, com verificações de proprietário/permissões. Não há chamadas de rede de teste.

Instalação opcional como comando, usando um ambiente virtual e ferramentas de
build disponíveis:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/nvg-scan --config config/local.json --format markdown
```

O build usa setuptools; o caminho com `PYTHONPATH=src` dispensa pip/setuptools e
funciona na live ISO com os fontes e Python presentes. A configuração não é
instalada implicitamente: a CLI sempre recebe seu caminho por `--config`.

### Códigos de saída

| Código | Significado |
| --- | --- |
| 0 | Todos os resultados emitidos são `pass` |
| 1 | Existe pelo menos um `fail`, mesmo que também existam warnings |
| 2 | Erro de argumentos, configuração ou escrita de saída |
| 3 | Há warnings e nenhum fail |

No subcomando `diff`, 1 significa novos fails, 3 novos warnings sem novos fails, e 0 ausência dessas regressões (inclusive quando um fail antigo permanece). Erros de entrada/saída usam 2.

Falhas de coleta/check ficam no relatório como warnings. Em CI, trate também
código 3 conforme a cobertura exigida. O processo pode produzir um relatório
completo e retornar 1 por encontrar configurações fora da política.

## Estrutura e arquitetura

```text
.
├── pyproject.toml
├── README.md
├── config/example.json        # Política genérica/legada
├── config/nos.json            # Política específica por ambiente/modo do nOS
├── src/nvg_scanner/
│   ├── __init__.py
│   ├── __main__.py             # CLI, destinos e códigos de saída
│   ├── engine.py               # Descoberta, isolamento de falhas e agregação
│   ├── diff.py                 # Comparação por ID, sem conteúdo de evidências
│   ├── nos.py                 # Aplicabilidade, usuário alvo e identidade da build
│   ├── nos_config.py          # Validação da política nOS
│   ├── nos_network.py         # Adaptador do verificador nativo
│   ├── network_state.py        # Snapshot de sockets compartilhado
│   ├── key_patterns.py         # Validação local de formatos/checksums
│   ├── data/                   # Wordlist BIP39 inglesa, licença e procedência
│   ├── models.py               # Result e contrato dos módulos
│   ├── config.py               # Validação JSON e composição de perfis
│   ├── collectors.py           # Arquivos, metadados e comandos locais
│   ├── scoring.py              # Score e cobertura
│   ├── reports.py              # JSON e Markdown
│   └── checks/
│       ├── __init__.py
│       ├── network_checks.py
│       ├── permissions_checks.py
│       ├── tor_checks.py
│       ├── service_checks.py
│       ├── kernel_checks.py
│       ├── account_checks.py
│       ├── firewall_checks.py
│       ├── package_integrity_checks.py
│       ├── key_exposure_checks.py
│       ├── vpn_checks.py
│       ├── vault_checks.py
│       ├── storage_checks.py
│       ├── nostr_agent_checks.py
│       └── installation_checks.py
├── examples/
│   ├── generate_reports.py
│   ├── report.json
│   └── report.md
└── tests/
    ├── __init__.py
    ├── fixtures.py
    ├── test_scanner.py
    ├── test_diff.py
    ├── test_firewall.py
    ├── test_packages.py
    ├── test_key_exposure.py
    ├── test_compatibility.py
    ├── public_key_vectors.json
    └── validate_real_diff.py
```

Configurações antigas sem as novas seções continuam produzindo os seis módulos e o score anteriores. Módulos opcionais declaram `CONFIG_SECTION` e só participam da execução padrão quando a seção tem `enabled: true`. Solicitar explicitamente um módulo desabilitado gera warning.

O motor descobre arquivos `*_checks.py` em `nvg_scanner.checks`, importa-os em ordem
determinística e consome `run(context)`. O contexto fornece configuração validada,
coletor substituível nos testes e cache local à execução. Um módulo pode retornar
lista ou iterador de `Result`. Se falhar durante a iteração, resultados anteriores
são preservados e um warning registra que o módulo não terminou; os demais seguem.

IDs são únicos dentro de uma execução. O prefixo `engine.` é reservado. Módulos
vazios, IDs duplicados e resultados inválidos produzem warning de execução. Plugins
são **código Python confiável**, com os privilégios do scanner: não há sandbox. A
configuração não pode indicar um arquivo Python arbitrário para importar.

Cada resultado serializa:

```json
{
  "id": "network.tcp.0.0.0.0.8332",
  "name": "Socket autorizado pela whitelist",
  "status": "fail",
  "severity": "high",
  "description": "Escuta ausente da whitelist.",
  "recommendation": "Identifique o serviço e restrinja o bind ou autorize a escuta necessária.",
  "evidence": {"protocol": "tcp", "address": "0.0.0.0", "port": 8332},
  "reason": null
}
```

`status` aceita `pass`, `fail`, `warning`; `severity` aceita `critical`, `high`,
`medium`, `low`, `info`. A severidade representa o impacto do controle, inclusive
quando ele passa. Warnings exigem `reason` para explicar a inconclusão ou contexto
necessário. IDs de recursos incluem endereço/unidade/usuário, permanecendo estáveis
enquanto a identidade do recurso não muda.

## O que os módulos verificam

| Módulo | Evidência e decisão |
| --- | --- |
| Rede | `ss -H -l -n -t -u`; listeners TCP e sockets UDP não conectados no namespace atual. Cada protocolo/endereço/porta deve estar na whitelist. |
| Permissões | Tipo, UID, GID opcional, máscara POSIX, symlinks e pais do caminho. Chaves não são abertas. ACLs encontradas ou inacessíveis geram warning de cobertura. |
| Tor | Unidade ativa com MainPID, binds SOCKS/DNS/Trans/Control, SafeSocks, autenticação declarada do ControlPort e nameservers de resolv.conf. |
| Serviços | UID efetivo do MainPID em `/proc`, comparado com exceções root e serviços que devem executar sem root. Root sem política gera revisão contextual. |
| Kernel | Valores efetivos de `/proc/sys` versus listas de valores aceitos na política. O motivo e a recomendação de cada parâmetro ficam no JSON. |
| Contas | UID 0 fora da política, shells interativos não justificados, campos de senha vazios e hashes legados reconhecidos. Senhas bloqueadas são descritas somente como bloqueio da autenticação por senha. |
| Firewall | Regras nftables JSON no hook input, políticas accept/drop e vereditos accept/drop/reject; whitelist e snapshot de sockets compartilhados. Construções não suportadas invalidam conclusões de proteção. |
| Pacotes | Políticas efetivas via pacman-conf, inventários locais, assinatura do artefato no cache e confiança do signatário via GPG offline. |
| Exposição de chaves | Arquivos selecionados do próprio usuário; nsec Bech32, WIF Base58Check e mnemônicos BIP39 ingleses com checksum. Apenas tipos, localização e contagens são reportados. |

### Interpretação e limites

- **Rede:** uma escuta não prova acessibilidade remota; firewall e rotas não são
  avaliados. Não há enumeração de outros namespaces ou scanners de portas ativos.
  UDP conectado, tráfego de saída e sockets Unix ficam fora desse módulo.
- **Permissões:** `max_mode` é máscara de bits permitidos, não comparação numérica
  nem modo exato: 0400 atende 0600. Bits especiais não são permitidos. Os pais
  devem pertencer a root ou ao UID esperado e não ser graváveis por grupo/outros;
  essa política estrita também sinaliza diretórios sticky como `/tmp`. Links são
  recusados por padrão; quando permitidos, as cadeias original e resolvida são
  revisadas. Diretórios sensíveis não são varridos recursivamente: liste arquivos
  relevantes individualmente. ACLs, mecanismos de acesso não POSIX, criptografia e
  backups não são integralmente auditados. O snapshot não elimina corridas de
  substituição de caminhos por processos concorrentes.
- **Tor:** o parser cobre diretivas simples e `%include` absoluto com arquivos,
  glob e diretórios, recursão limitada e detecção de ciclos. Continuação de linha,
  includes relativos e operadores `+`/`/` geram inconclusão da configuração.
  Endpoints `auto`/Unix geram revisão específica. Ele não substitui o parser
  oficial nem valida todas as diretivas do Tor. O perfil de binds é para cliente
  local; configurações de gateway precisam de política/check adaptado.
- **DNS:** nameserver local, DNSPort ou SafeSocks não demonstram ausência de
  vazamento. Não são validados upstream de stubs, regras de firewall, DoH/DoT,
  resolução própria das aplicações ou todos os caminhos IPv6. Por isso
  `tor.dns_assurance` permanece warning. Não é feito teste de tráfego DNS.
- **Configuração efetiva:** Tor pode usar defaults, argumentos de linha de
  comando ou configuração ainda não recarregada. Isso e o bootstrap ficam
  explicitamente inconclusivos. Passes do parser descrevem o arquivo selecionado.
- **Serviços:** só processos principais de unidades systemd `running` do sistema;
  processos filhos, gerenciadores de usuário e daemons externos não são cobertos.
  `User=root` não basta para reprovar: um daemon pode abandonar privilégios.
- **Kernel:** valores ausentes, por exemplo Yama não compilado, geram warning.
  A política de exemplo não é um benchmark CIS nem uma lista completa. Parâmetros
  `all` de rede não dispensam revisão das interfaces e dos valores `default`.
- **Contas:** só os arquivos locais configurados, sem NSS/LDAP. Shell habilitado
  não prova falta de uso nem possibilidade de login. Hash não revela força da
  senha. PAM/SSH, expiração e MFA não são auditados nesta versão; não há cracking.
  A lista de prefixos legados é política editável, não avaliação completa de KDFs.

## Configuração e perfis

O documento exige `schema_version: 1`, `defaults` e `profiles`. Dicionários do perfil
são mesclados recursivamente; **listas são substituídas por inteiro**. O perfil
`installed` herda os defaults. O `live` lista somente `/etc/shadow` entre os caminhos
sensíveis, pois o exemplo não presume carteiras ou chaves pessoais numa ISO.
Ele não autoriza automaticamente senha vazia, serviços root ou portas adicionais.

Campos desconhecidos nas seções nativas são rejeitados para evitar erros de
digitação silenciosos. As seções opcionais nativas são `firewall`, `package_integrity` e `key_exposure`. Use `extensions` para políticas de outros módulos.

Exemplo de regra de rede adicional (adicione à lista apropriada):

```json
{"protocol": "tcp", "address": "127.0.0.1", "port": 8332, "comment": "RPC local, se necessário nesta instalação"}
```

`address` aceita IP literal, CIDR ou `*`. A regra só autoriza o protocolo e a porta
indicados; nenhuma regra exige que a porta esteja aberta. Endereços loopback não
autorizam wildcard. Use `*` apenas quando desejar permitir qualquer bind. CIDRs
que incluem o endereço não especificado, como `::/64`, não autorizam por acidente
um bind em todas as interfaces; CIDR `/0` e o endereço wildcard literal são explícitos.
IPv4 e IPv6 são comparados separadamente; o escopo de um IP IPv6 não restringe a
whitelist a uma interface específica.

`permissions.sensitive_paths` aceita `id`, `path` absoluto, `kind` (`file` ou
`directory`), `max_mode` octal em string, `uid`, `gid` opcional, `required`,
`allow_symlink` e `severity`. Ausência obrigatória falha; ausência opcional gera
warning por não permitir avaliação. Tor usa a unidade e caminhos definidos em
`tor`; `allowed_nameservers` autoriza somente os endereços declarados no resolver,
sem afirmar que pertencem ao Tor.

Em `services`, `allowed_root_services` e `require_non_root` são listas de nomes
exatos de unidades, sem glob e sem interseção. Uma unidade que não está em execução
não é avaliada por esse módulo. A disponibilidade do Tor tem check próprio.

## Score e cobertura

Os pesos do exemplo são critical=10, high=5, medium=3, low=1, info=1. São inteiros
positivos configuráveis. Para os **resultados emitidos**:

```text
score = 100 × soma(pesos dos pass) / soma(pesos dos pass e fail)
cobertura = 100 × quantidade(pass e fail) / quantidade(total)
cobertura ponderada = 100 × soma(pesos dos pass e fail) / soma(pesos totais)
```

Warnings são excluídos do score e reduzem a cobertura. Sem resultados conclusivos,
o score é `null`; cobertura de execução vazia é zero. A cobertura não é uma medida
de todos os controles possíveis de segurança: refere-se aos resultados emitidos.
Ela inclui avisos de escopo para evitar omissões silenciosas.

Score é conformidade com esta política, não uma probabilidade de segurança ou
certificação. A quantidade de contas, sockets e caminhos muda o denominador; não
compare diretamente hosts ou seleções de módulos diferentes. Compare execuções
com a mesma política, escopo e inventário, revisando também falhas críticas e
warnings. Um `pass` em outra categoria não neutraliza uma falha crítica.

## Exemplos e testes

Os relatórios completos em [examples/report.json](examples/report.json) e
[examples/report.md](examples/report.md) vêm de um host **sintético**: Tor local,
porta adicional fora da whitelist, chave com modo 0644 e uma conta com campo de
senha vazio. Eles não contêm uma coleta real desta máquina.

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m examples.generate_reports
PYTHONPATH=src python3 -m examples.generate_improvements
```

Os testes usam `unittest`, coletores simulados e arquivos temporários. Cobrem
whitelists IPv4/IPv6, permissões e ACLs, includes Tor, autenticação de controle,
DNS inconclusivo, leitura de UIDs, contas, score, descoberta de módulos, isolamento
de falhas, validação da política e proteção da saída. Não exigem root ou serviços
ativos. Validar numa live ISO real e numa instalação NVG OS continua sendo a etapa
de integração necessária antes de distribuir a ferramenta na imagem.

## Adicionar um módulo

1. Crie `src/nvg_scanner/checks/example_checks.py`.
2. Exporte `run(context)` e gere resultados com IDs próprios, estáveis e únicos.
3. Coloque parâmetros próprios em `defaults.extensions.example` e valide-os no
   módulo. Nunca registre conteúdo de arquivos secretos em evidências/exceções.
4. Adicione testes para falhas reais e evidência inacessível, depois execute a CLI.

Exemplo de módulo que observa se o namespace tem swap habilitado:

```python
from nvg_scanner.collectors import Unavailable
from nvg_scanner.models import Result, inconclusive


def run(context):
    # Swap pode persistir dados privados; /proc/swaps sozinho não prova se há
    # criptografia. A presença exige contexto em vez de reprovação automática.
    try:
        lines = context.collector.read_text("/proc/swaps").splitlines()
    except Unavailable as error:
        yield inconclusive("example.swap", "Swap", str(error))
        return
    if not lines or not lines[0].startswith("Filename"):
        yield inconclusive("example.swap", "Swap", "Formato de /proc/swaps desconhecido.")
    elif any(line.strip() for line in lines[1:]):
        yield inconclusive("example.swap", "Swap", "Swap presente; criptografia e persistência não avaliadas.")
    else:
        yield Result("example.swap", "Swap", "pass", "medium",
                     "Nenhuma área swap listada no snapshot.",
                     "Preserve a política de proteção de dados em memória.")
```

```sh
PYTHONPATH=src python3 -m nvg_scanner --list-checks
PYTHONPATH=src python3 -m nvg_scanner \
  --config config/local.json --checks example_checks --format markdown
```

Não é necessário alterar o motor, o cálculo de score ou os serializadores.
Para testar, injete um coletor controlado em `Context`, como em `tests/fixtures.py`.

## Referências técnicas

- [nftables](https://netfilter.org/projects/nftables/manpage.html) e
  [schema JSON](https://man.archlinux.org/man/libnftables-json.5.en).
- [pacman](https://man.archlinux.org/man/pacman.8.en),
  [pacman-conf](https://man.archlinux.org/man/pacman-conf.8.en) e
  [opções GPG](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html).
- [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md),
  [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) e
  [WIF](https://en.bitcoin.it/wiki/Wallet_import_format).

- [Manual do Tor distribuído pelo Arch](https://man.archlinux.org/man/tor.1.en):
  sintaxe torrc, includes, precedência de opções, SafeSocks e endpoints.
- [Documentação do kernel — sysctl kernel](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html):
  ASLR e restrições de informações do kernel.
- [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html): coleta passiva de sockets.
- [shadow(5)](https://man7.org/linux/man-pages/man5/shadow.5.html): significado dos
  campos de credenciais locais.

## 1. Diff entre execuções

`diff.py` compara a união dos IDs, validando schema, status, severidades, métricas
finitas e unicidade de IDs. Não carrega módulos de checks nem requer configuração,
privilégios ou ferramentas de sistema. Aceita os relatórios 1.0 já existentes.

```sh
PYTHONPATH=src python3 -m nvg_scanner diff \
  --before reports/execucao1/report.json \
  --after reports/execucao2/report.json \
  --format both --output reports/diff-1
```

O diretório novo recebe `diff.json` e `diff.md`, com as mesmas proteções contra
sobrescrita e modo 0600 dos relatórios de auditoria. Entradas são limitadas a
32 MiB cada. Erros não reproduzem conteúdo dos documentos.

| Antes → depois | Classificação |
| --- | --- |
| pass/warning → fail | `new_fail` |
| fail → pass | `resolved_fail` |
| pass/fail → warning | `new_warning`; fail não foi resolvido |
| warning → pass | `resolved_warning` |
| Mesmo status, nenhum campo alterado | `unchanged` |
| Mesmo status, severidade/texto/evidência alterados | `changed` |
| ID só no atual | `presence: added`, mais `new_fail`, `new_warning` ou `added_pass` |
| ID só no anterior | `presence: removed`, sem presumir correção |

As contagens de presença e transição são dimensões diferentes: um novo fail pode
também ser um resultado adicionado. Não some todas as contagens como se fossem
categorias mutuamente exclusivas. Um ID ausente pode refletir falha de coleta,
troca de perfil, seleção de módulos ou mudança do recurso. O scanner não distingue
essas causas automaticamente.

Score, cobertura e cobertura ponderada mostram antes/depois/delta, em pontos
percentuais. Se qualquer extremo for `null`/ausente, o delta é `null`. Mudanças de
perfil, módulos, versão do scanner ou pesos geram aviso de comparabilidade. Os
relatórios antigos não registram toda a política; perfis iguais não provam
políticas iguais.

O diff **não copia** nomes descritivos, textos, recomendações ou conteúdo de
evidências. Registra somente quais campos mudaram, status/severidade antes/depois
e o ID. Nomes de arquivos/IDs que parecem conter material sensível são omitidos
por inteiro. Não há comparação por chave, fingerprint ou hash de segredo. Duas
chaves diferentes do mesmo formato no mesmo arquivo, com a mesma contagem, podem
resultar em `unchanged`: não se tenta identificar qual chave foi encontrada.

Exemplos: [JSON](examples/diff.json) e [Markdown](examples/diff.md).

### Validação real anterior aos novos módulos

Antes de implementar firewall, duas execuções reais dos seis módulos legados
foram comparadas. Arquivos descartáveis vazios tiveram seus modos/presença
alterados; `Collector`, `permissions_checks` e o motor produziram os resultados,
sem mocks ou edição de status nos JSONs. Foram confirmadas seis transições:
fail→pass, warning→pass, fail→warning, pass→fail, pass→warning e warning→fail.

O teste inicialmente encontrou `/home` com proprietário incompatível neste
ambiente. Essa reprovação foi preservada; a coleta de transições usou outro
diretório temporário com ancestrais seguros. Nenhuma configuração do host foi
alterada. Os arquivos de antes/depois e o diff estão em
`reports/diff-real-validation-sub7hna_/` nesta workspace (dados locais, ignorados
pelo Git). Os quatro testes unitários iniciais também passaram antes do firewall.

Para reproduzir essa integração, com saída em um novo diretório de `reports/`:

```sh
PYTHONPATH=src python3 -m tests.validate_real_diff
```

Ela exige um diretório gravável com ancestrais seguros e não tenta corrigir o
sistema caso nenhum exista. Evidências antigas que apontam arquivos temporários
são snapshots: os arquivos do teste são removidos ao final.

## 2. Firewall/nftables

A seção `firewall` do exemplo habilita o módulo e exige entrada fechada por padrão
para IPv4 e IPv6:

```json
{
  "enabled": true,
  "require_default_deny": true,
  "require_ipv6": true,
  "accept_justifications": {}
}
```

`accept_justifications` aceita justificativas não vazias por família (`ip`, `ip6`).
Uma exceção autoriza a política ACCEPT, mas não autoriza automaticamente sockets
ou regras fora de `network.allowed_listeners`. A whitelist mantém protocolo,
porta e endereço; uma regra de entrada sem restrição de destino pode ser mais
ampla que uma whitelist de bind em loopback.

A coleta executa `nft -j -n list ruleset` sem shell, sem resolução de nomes e com
timeout. O módulo encontra chains pelo hook `input`, não pelo nome. No subconjunto
suportado, respeita a ordem das regras e vereditos terminais. `reject` é veredito
de regra; **policy de chain só pode ser `accept` ou `drop`**. Regra terminal
incondicional de reject/drop pode constituir o fechamento padrão.

São interpretados protocolo TCP/UDP, porta literal, destino IP/CIDR, contadores e
vereditos accept/drop/reject. Uma regra permitida também é comparada à whitelist
quando ainda não existe listener. Para sockets, o relatório identifica veredito e
se a cobertura veio de regra ou policy. Default DROP cobre um socket mesmo sem
regra individual. ACCEPT sem regra explícita de cobertura é sinalizado.

### Interpretação e limites do firewall

- NAT, conntrack/estado de conexão, interfaces, saltos, sets/maps/flowtables
  nomeados, intervalos de portas e outras expressões fora do modelo produzem
  motivos específicos: o relatório identifica o índice do registro e a construção.
- Múltiplas base chains sobrepostas numa mesma família, hooks anteriores ao input
  e flags como `dormant` também invalidam a conclusão. Uma chain ip e outra ip6
  independentes podem ser avaliadas; inet sobreposta a ip/ip6 gera warning.
- **Havendo qualquer construção não suportada no escopo identificado, o módulo
  emite warnings e não produz passes de proteção para esse ruleset.** Isso é
  deliberadamente conservador, inclusive para sets declarados aparentemente sem
  uso. Há testes dedicados para esses caminhos de inconclusão.
- Socket wildcard com regras de destino parcial pode exigir warning específico.
  Tráfego de saída/forward, iptables legado, outros namespaces, outros mecanismos
  de filtragem e acesso real pela rede não são comprovados. Nenhum pacote de teste
  é enviado. `ss` e `nft` são snapshots próximos, não uma transação atômica.
- IDs das regras usam posição; mudanças na ordem podem aparecer como alterações
  no diff. IDs de sockets usam protocolo/endereço/porta.

Exemplos: [JSON](examples/firewall.json) e [Markdown](examples/firewall.md).

## 3. Integridade de pacotes e confiança GPG

`package_integrity_checks.py` usa os executáveis mantidos pelo sistema `pacman`,
`pacman-conf` e `gpg`. Não há biblioteca Python externa de criptografia ou parsing
pacman. Todas as consultas operam sobre arquivos e bases locais, sem sincronização.

```json
{
  "enabled": true,
  "pacman_conf": "/etc/pacman.conf",
  "db_path": "/var/lib/pacman",
  "keyring_dir": "/etc/pacman.d/gnupg",
  "cache_dirs": ["/var/cache/pacman/pkg"],
  "max_packages": 128
}
```

`pacman-conf` resolve includes/herança da política de assinatura. O scanner exige
PackageRequired e PackageTrustedOnly nas configurações avaliadas, incluindo
LocalFileSigLevel e repositórios configurados. Políticas permissivas geram fail;
valores não interpretados geram warning.

`pacman -Q` enumera versões instaladas; `pacman -Sl` consulta as bases locais dos
repositórios. Ausência de um nome nessas bases gera warning de severidade info.
Não se presume que o pacote veio do AUR ou de `-U`: uma base desatualizada, pacote
removido ou repositório NVG OS também pode explicar a diferença.

A reverificação exige um único candidato de arquivo comprimido no cache, da mesma
versão, confirmado por `pacman -Qp`, e sua assinatura destacada `.sig`. Sem arquivo,
assinatura, ferramenta ou keyring, o resultado é warning. Não se inventa um pass a
partir de metadados históricos de validação. Pacotes com múltiplos candidatos no
cache também ficam inconclusivos, para não escolher um artefato arbitrariamente.

O GPG trabalha numa cópia temporária privada de `pubring.gpg`/`pubring.kbx` e
`trustdb.gpg`; nenhuma chave privada é copiada. Configurações GPG do usuário são
ignoradas, aquisição/importação automática de chaves e dirmngr ficam desabilitados.
A chave e a base de confiança originais não são modificadas. Só tokens de status
GPG são interpretados; mensagens com identidades de signatários não são reportadas.

Assinatura válida com TRUST_FULLY/TRUST_ULTIMATE passa. BADSIG, revogação/expiração
local ou confiança insuficiente geram fail. Ausência de chave ou confiança
indeterminada gera warning. A validade/confiança do signatário não é confundida
com o ownertrust de cada chave isoladamente.

### Interpretação e limites dos pacotes

A assinatura é do **arquivo no cache**, não dos bytes atualmente instalados. Esta
versão não implementa comparação de arquivos instalados, garantia da procedência
histórica, atualização do keyring nem consulta online de revogações. Cache e banco
de dados locais são evidência local, não uma raiz de confiança independente de
um host comprometido. Backends keyboxd sem pubring acessível não são suportados.

`max_packages` limita quantos pacotes terão verificação criptográfica, em ordem
de nome; atingir o limite gera warning. Inventário/avisos foreign ainda podem
abranger os demais. Cada comando tem o timeout global configurado, portanto uma
verificação completa pode demorar. Diretórios de cache/keyring configurados devem
corresponder à instalação que se pretende auditar. Não há tentativa de corrigir,
baixar ou reinstalar pacotes.

Exemplos: [JSON](examples/package_integrity.json) e
[Markdown](examples/package_integrity.md).

## 4. Exposição de material de chave no nOS

É um módulo separado porque lê conteúdo, enquanto `permissions_checks.py` continua
sem abrir chaves privadas. `key_exposure` vem **desabilitado** no exemplo; habilite-o
na sua configuração quando desejar auditar os arquivos selecionados.

```json
{
  "enabled": false,
  "home_dir": null,
  "paths": [
    {"id": "bash_history", "path": "~/.bash_history"},
    {"id": "zsh_history", "path": "~/.zsh_history"}
  ],
  "max_file_bytes": 262144,
  "max_total_bytes": 1048576,
  "max_files": 8,
  "max_seconds": 5,
  "max_directory_entries": 128
}
```

`home_dir: null` usa o home cadastrado para o UID efetivo do scanner. Com sudo,
isso normalmente é root: defina `home_dir` explicitamente para auditar o usuário
nOS pretendido. Não usamos HOME fornecido pelo ambiente nem enumeramos todos os
usuários.

`paths` aceita arquivos absolutos ou `~/...`. Um glob somente no componente final,
como `/tmp/nvg-*.log`, é permitido quando explicitamente adicionado. Glob em
diretórios ancestrais e `**` são rejeitados. Diretórios de log, `/tmp`, backups,
outros usuários e clipboard não são selecionados automaticamente. Há no máximo
128 entradas examinadas por seleção de diretório no exemplo; atingir o limite
gera warning. A ordem limitada de enumeração pode não cobrir todos os matches.

Somente arquivos regulares são lidos. O componente final não pode ser symlink;
FIFO e dispositivos são rejeitados sem leitura de conteúdo. Ancestrais do caminho
podem conter links: configure caminhos confiáveis. Não há extração de arquivos
comprimidos nem recursão. Limites de bytes incluem o conteúdo analisado; há uma
sondagem adicional de até um byte por arquivo para detectar truncamento.

Limites padrão são aplicados desde v1 e têm tetos de configuração: 1 MiB por
arquivo, 8 MiB por execução, 64 arquivos, 30 segundos e 1.024 entradas por seleção.
O prazo é verificado entre operações e durante a análise; não interrompe uma
chamada de filesystem bloqueada pelo kernel. Arquivos alterados durante leitura,
inacessíveis, incompletos e limites atingidos nunca viram aprovação silenciosa.

### Formatos, severidade e confidencialidade

- Nostr: nsec Bech32, checksum e comprimento; não interpreta ncryptsec.
- Bitcoin: WIF mainnet/testnet, Base58Check, tamanho e intervalo da chave.
- BIP39: frases de 12/15/18/21/24 palavras inglesas contíguas, com checksum.
  A wordlist incorporada tem commit e SHA256 próprios em
  `src/nvg_scanner/data/PROVENANCE.txt`; esse hash é do conjunto público de dados,
  nunca de um segredo encontrado. Não há downloads em execução. Outros idiomas,
  palavras reordenadas/abreviadas ou fragmentos curtos não são cobertos.

Um padrão válido gera fail **critical**, mesmo se o arquivo for 0600: a política
audita plaintext em históricos/logs selecionados, não apenas leitura por terceiros.
Check válido não prova que há fundos ou que o material é usado: exemplos públicos
e vetores de teste também serão sinalizados. Candidatos nsec/WIF sem checksum
confirmado geram warning critical. Um pass significa apenas que os padrões
suportados não foram encontrados no arquivo integralmente lido.

A evidência limita-se a tipo, caminho e contagem. Não contém trecho, prefixo,
linha de conteúdo, hash, fingerprint ou valor derivado que identifique a chave.
Isso vale para relatórios, logs internos/stdout/stderr e diff. Se o próprio nome
do arquivo/ID parecer conter material sensível, o rótulo inteiro é omitido.
O diff informa mudanças nos campos permitidos e não tenta reconstruir valores,
relacionar a mesma chave entre arquivos ou aproximar uma chave a partir de outra.

Nenhum conteúdo lido é deliberadamente escrito em arquivos temporários. Entretanto,
Python não oferece limpeza garantida de memória: esta regra de persistência se
refere às saídas da ferramenta, não a swap, dumps do processo ou instrumentação
externa. O scanner não altera esses mecanismos do sistema.

Exemplos: [JSON](examples/key_exposure.json) e [Markdown](examples/key_exposure.md).
O arquivo `tests/public_key_vectors.json` contém apenas vetores públicos de teste
NIP-19/BIP39/WIF; não deve ser usado para guardar chaves reais.

## Validação desta implementação

A suíte atual inclui os testes da versão anterior e os contratos nOS descritos abaixo. Além dos coletores simulados, há testes de leitura
real de arquivos/FIFO/symlinks e uma integração GPG que gera uma chave descartável
num diretório temporário, assina dados de teste, verifica a assinatura, altera os
dados e confirma a reprovação. O teste confirma também que keyring público/trustdb
de origem permanecem byte a byte iguais após as verificações. O agente GPG do
teste é encerrado e os arquivos temporários são removidos. Esse teste é ignorado
explicitamente se `gpg`/`gpgconf` estiverem ausentes.

Na validação da versão 0.2 passaram 72 testes, incluindo a integração GPG. `nft`, `pacman`
e `pacman-conf` não estavam disponíveis; seus casos de sucesso/falha/inconclusão
foram exercitados com coletores simulados. A integração desses comandos numa ISO
ou instalação NVG OS continua pendente. A validação real do diff ocorreu antes
da implementação do firewall, conforme descrito acima.

## Integração nOS 0.3

A política [config/nos.json](config/nos.json) deriva dos documentos fornecidos em
[Context-for-CODEX/NVG-Doc](Context-for-CODEX/NVG-Doc/README.md), especialmente
[rede](Context-for-CODEX/NVG-Doc/verificacao-estado-rede.md),
[base Arch](Context-for-CODEX/NVG-Doc/base-arch.md),
[agente](Context-for-CODEX/NVG-Doc/agente.md) e
[pós-instalação](Context-for-CODEX/NVG-Doc/heranca-do-live.md).
A documentação descreve uma árvore em desenvolvimento; não comprova que a ISO
instalada contenha esses componentes. `config/example.json` permanece disponível
para compatibilidade. Seções nOS ausentes não habilitam os novos módulos.

### Ambiente e intenção

```sh
cp config/nos.json config/nos-local.json
PYTHONPATH=src python3 -m nvg_scanner \
  --config config/nos-local.json --profile installed --target-user joao \
  --preset quick --format both --output reports/nos-quick-01
PYTHONPATH=src python3 -m nvg_scanner \
  --config config/nos-local.json --profile tor --target-user joao \
  --preset full --format both --output reports/nos-tor-01
```

Substitua `joao` pela conta local auditada. Sem `--target-user`/`nos.target_user`,
usamos a conta do UID efetivo; execução root exige alvo explícito para checks de
usuário. Não inferimos identidade por HOME ou SUDO_UID. `~` nos caminhos sensíveis
é expandido para esse usuário; `uid: "target"` compara o proprietário correto.
Consultas de permissões não abrem o conteúdo de `chave.ncryptsec` nem de carteiras.

Perfis fornecidos: `installed`, `live`, `install-media`, `tor`, `vault-live` e
`vault-installed`. Os perfis continuam substituindo listas integralmente. Cada
perfil declara ambiente **esperado**; não é autodetecção nem seleção automática
baseada num marcador. `context.os_release` registra separadamente ID/versão/build
observados, e `context.release_packages` registra versões locais dos componentes
quando pacman está disponível. `null` significa versão não obtida/ausente, não uma
versão atualizada. Os pacotes não são atualizados nem consultados online.

`nos.expected_network_mode` aceita `base`, `tor`, `killswitch-tor`,
`killswitch-vpn` ou `airgap`. Vault exige `airgap`. Para VPN, configure interface e
lista explícita `vpn_endpoints` com pares `[IP literal, porta UDP]`: esses valores
são passados ao verificador para comparação, sem descobrir ou liberar endpoints
automaticamente. Não há perfil VPN pré-ativado com endpoints fictícios.

`nos.features` torna identidade Nostr, relay e Bitcoin explícitos. Identidade é
opcional e desabilitada no exemplo. Habilite-a apenas para uma conta que deveria
ter chave/agente provisionados. Bitcoin habilita os caminhos de exemplo de
carteira/configuração: ajuste-os ao layout real antes do uso. Relay é esperado no
perfil instalado de soberania; seus listeners e runtime são conferidos somente
nesse escopo. Instalar um pacote não comprova configurar um nó.

Tor só é exigido nos modos `tor` e `killswitch-tor`. O módulo genérico continua
conservador, mas o complemento nOS confronta UID efetivo com `nos.tor_uid` (43 na
referência documentada), verifica listeners locais UDP/9053 e TCP/9040 e consulta
upstreams do resolvedor sem enviar DNS de teste. `127.0.0.53` é permitido como
stub declarado no exemplo, mas nunca basta para aprovar ausência de vazamento.
Referências de firewall, UID e destinos locais precisam ser revisados juntos ao
alterar a política distribuída.

### Verificador nativo e fronteira de confiança

Com `firewall.backend: "nos"`, o scanner chama o contrato documentado
`network_verify MODE`, da biblioteca `/usr/lib/neovanguard/neo-rede.sh`.
Exige arquivo e ancestrais root, sem escrita de grupo/outros ou symlinks, tanto
para biblioteca quanto para referência. Essa checagem protege a seleção de código;
não autentica o pacote contra root comprometido. A biblioteca e suas dependências
fazem parte da base de confiança do OS. Os caminhos são configuráveis.

O adaptador exige `schema_version: 1`, timestamp recente, modo solicitado correto,
estado conhecido e coerência do código de saída. Só `verification.state` decide:
`verified → pass`, `mismatch → fail`, `unknown → warning`. Um perfil customizado
pode ser seguro e ainda divergir do perfil exigido: o fail é de conformidade.
Campo ausente, JSON inválido, cache antigo, referência insegura e contradições
produzem warning específico, sem fallback positivo. Motivos fornecidos pelo
verificador são limitados e filtrados; ausência de motivo também é declarada.

O SHA-256 registrado identifica somente a **referência pública** de regras lida
na execução; não é hash de segredo nem autenticação externa dessa referência.
Marcadores de `/run` não são usados. O scanner não chama apply/cache, Tor on/off,
kill-switch, desbloqueio, assinatura ou publicação Nostr. O backend `generic`
permanece disponível e mantém warnings para construções não interpretadas.

### Novos controles e limites

| Módulo | Evidência e limite |
| --- | --- |
| `vpn_checks` | Interface administrativa, endpoints WireGuard e handshakes recentes; UP ou regras reconhecidas não comprovam conectividade. Peers ociosos/sem handshake e outras VPNs UDP permanecem inconclusivos. |
| `vault_checks` | Flags administrativas de interfaces e bloqueio soft/hard de rádios. Atividade conhecida continua fail diante de outra evidência ausente. Nenhuma mudança de interface/rádio. |
| `storage_checks` | Montagens tmpfs/opções efetivas, swap e backing de ZRAM, configuração composta journald. Swap em disco/writeback fica inconclusivo até revisão de sua cadeia de criptografia. |
| `nostr_agent_checks` | Unidade do usuário, NoNewPrivileges, ProtectSystem, ProtectHome, listas simples de famílias/escrita, runtime e socket. Não valida prompt, expiração, SO_PEERCRED ou equivalência de filtros complexos. |
| `installation_checks` | liveuser, lista de resíduos/serviços, montagem temporária sobre chaveiro, autologin direto root, declarações sudo/SDDM e fstab por destino. Includes/aliases/wrappers não resolvidos impedem uma aprovação global. |

`nos.agent_socket` começa como `null`: o documento fornecido informa o diretório,
mas não o nome do socket. Depois de conferir o pacote instalado, informe somente
o nome do arquivo no runtime. Até lá, o check permanece warning. Não exigimos
`MemoryDenyWriteExecute`, respeitando a exceção QML/JIT documentada.

`kernel_checks` aceita listas homogêneas de inteiros **ou strings**, permitindo
verificar `kernel.core_pattern`. O perfil nOS acrescenta BPF/perf e exige
`ptrace_scope=2`. Valores de desempenho de ZRAM/swappiness não foram convertidos
em indicadores de segurança sem justificativa. Política de módulos compilados,
initramfs efetivo, LUKS/Secure Boot e teste de boot/hardware não são comprovados
por esta implementação.

O Vault instalado mantém a raiz em disco. Nem `copytoram`, tmpfs, ZRAM ou a marca
Vault certificam ausência de persistência. A configuração journald composta não
comprova que o processo já a recarregou. Flags de mounts não comprovam criptografia.
Listas de artefatos pós-instalação precisam acompanhar `strip_live` da build real.

### Cobertura criptográfica de pacotes

`summary.package_coverage` está presente no JSON e destacado antes dos achados no
Markdown. O limite de seleção continua configurável; pacotes prioritários entram
antes do corte. Nenhum contador transforma tentativa ou política permissiva em
verificação concluída.

| Campo | Significado |
| --- | --- |
| `total_installed` | Total do inventário local; null se indisponível. |
| `selected` | Pacotes selecionados para o caminho de verificação, após o limite. |
| `examined` | Selecionados cujo processamento começou. |
| `verification_attempts` | Chamadas ao caminho de GPG, inclusive indisponibilidade de keyring/assinatura. |
| `cryptographically_verified` | Pacotes com evidência GPG VALIDSIG ou BADSIG. Inclui verificação negativa. |
| `valid_signatures` / `invalid_signatures` | Resultados matemáticos válidos/inválidos; expiração/revogação sem evidência matemática conclusiva não aumenta cobertura. |
| `trusted_valid_signatures` | Assinatura válida e confiança suficiente no estado local. |
| `inconclusive` | Examinados sem resultado criptográfico conclusivo. |
| `not_verified` | Total instalado menos verificados, incluindo os fora do limite. |
| `coverage_percent` | 100 × verificados / total instalado; null se total desconhecido. |

Exemplo: **130 instalados, 128 selecionados, 128 examinados, 1 verificado e 129
não verificados**. O arquivo faltante no cache não aumenta cobertura.
Exemplos completos: [JSON](examples/package_coverage.json) e
[Markdown](examples/package_coverage.md). Cobertura dos artefatos em cache **não é
cobertura dos bytes instalados**, nem garantia de procedência histórica.

Na seleção rápida, os módulos de pacote/chaves ficam explicitamente omitidos.
Se o inventário já estiver disponível pela identificação da build nOS, o total
aparece com zero verificações; caso contrário, permanece desconhecido. O diff
mostra deltas numéricos de total e verificações, além de avisar sobre mudanças de
contexto/seleção. Nunca copia campos livres, credenciais ou referências a valores
anteriores de segredo.

### Custo de execução, score e extensão

`execution` configura `max_seconds` (120 no exemplo), `max_output_bytes` (8 MiB
por consulta) e `preset` (`quick`/`full`). Stdout de subprocessos é limitado em
blocos; stderr é descartado sem persistência. Timeout mata o grupo da consulta.
Arquivo especial/FIFO não é aberto para leitura bloqueante. O orçamento de tempo
é cooperativo entre módulos e aplicado a subprocessos; chamadas de filesystem
presas no kernel e código Python arbitrário de plugins não têm preempção rígida.

Consultas systemd usam lotes no perfil nOS e revalidam PID; `ss` é compartilhado
por rede/firewall/Tor/relay e mountinfo por armazenamento/instalação. A cópia
privada do chaveiro GPG é reutilizada apenas durante o scan e removida ao final,
inclusive em interrupção. Não há cache de confiança entre execuções.

Módulos podem declarar `SCAN_PRIORITY` (menor executa primeiro, padrão 50) e
`RUN_IN_QUICK = False`. Checks de chave e assinatura ficam depois dos controles
do host, evitando que GPG consuma o orçamento antes de rede e permissões.
`--checks` explícito preserva a ordem solicitada e permite executar um módulo
caro mesmo com preset quick. Módulo explicitamente solicitado mas não aplicável
produz warning; não altera silenciosamente o modo esperado.

`summary.score` mantém a fórmula anterior para compatibilidade. Os campos
`domains`, `domain_balanced_score` e `critical_failures` complementam a leitura:
cada domínio tem score/cobertura e contribui igualmente à média equilibrada.
Adicionar centenas de passes de pacotes não aumenta o peso daquele domínio sobre
rede. Warnings continuam fora das médias, portanto scores não são certificados.
A lista `selection.omitted` explicita controles não executados; esses controles
não recebem passes artificiais nem entram na cobertura dos resultados emitidos.

A identificação de política usa `nos.policy_version`: incremente-a ao alterar a
política local. Não fazemos hash de toda a configuração, pois ela pode conter
caminhos ou valores privados. Duas políticas alteradas sem mudança dessa versão
podem ter diferenças que os metadados do diff não identificam.

### Exposição de credenciais adicionais

O detector mantém os mesmos limites de bytes, arquivos e tempo. Reconhece URI
`bunker://` com chave pública estruturalmente válida e parâmetro secret não vazio
como credencial exposta, sem contatar relay. Partes `nvgs1`/`nvgs2` são candidatas
por prefixo e geram warning/high: CRC/formato integral não foram inferidos da
documentação, não são agrupadas e nunca se reconstrói uma seed. `ncryptsec`
cifrado não é tratado como chave em claro. Não lemos o clipboard/Klipper; seus
atalhos no desktop não autorizam ampliar a leitura do usuário.

A mesma omissão de rótulos potencialmente sensíveis cobre nomes de arquivos/IDs
com bunker ou Shamir. Logs internos, JSON, Markdown e diff não persistem URI,
segredo, parte, fragmento nem hash desse material. O detector trabalha em memória;
não garante apagamento de cópias Python, swap ou dumps externos ao scanner.

### Validação 0.3 e integração ainda necessária

Os testes em `tests/test_nos.py` cobrem cobertura parcial e desconhecida, prioridade
de pacotes, contratos nativos contraditórios/antigos/sem permissão, rádio ausente,
interface administrativamente UP com operstate DOWN, configurações de montagem,
writeback de ZRAM, journald composto, socket/usuário, sudo/SDDM/fstab, supressão de
segredos e orçamento. Os testes GPG verificam também uma única cópia do chaveiro
por execução e sua limpeza, mantendo o original intacto.

Há um smoke test real do scanner neste ambiente em
`reports/nos-validation-20260913-v1/`, sem erros internos de módulos. O ambiente
identificou-se como `org.freedesktop.platform`, **não como nOS**; ausências de
pacman, verificador nativo e outras evidências ficaram explícitas. Isso testa a
execução e a degradação de cobertura, não a integração na distribuição.

Na ISO/instalação nOS, ainda é necessário conferir o nome do socket, os arquivos
da biblioteca e seu esquema real, UID/listeners Tor, gerenciador systemd de
usuário, keyring pacman e listas de resíduos. Os fontes do OS referenciados pela
documentação e uma ISO executável não estão neste workspace. Nenhum relatório
sintético foi apresentado como validação de boot, anonimato ou hardware.

Resultado desta rodada: **107 testes aprovados**, incluindo GPG real; wheel
`nvg_hardening_scanner-0.3.0-py3-none-any.whl` construído e importado isoladamente
com 14 módulos e as 2048 palavras BIP39. O scan completo 0.3 em
`reports/nos-validation-20260913-v03-full/` terminou sem erros internos de módulos
(exit 1 por divergências da política). O diff 0.3 reaplicado aos relatórios reais
anteriores preservou as seis transições esperadas; artefatos em
`reports/diff-compat-v03/`. Esses diretórios de relatórios locais são ignorados
pelo projeto, e não devem ser tratados como exemplos portáveis da ISO.
