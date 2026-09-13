# Auditoria de hardening — NVG OS

Perfil: installed  
Data UTC: 2026\-09\-12T12:00:00\+00:00

**Score de conformidade: 82.14/100**  
Cobertura por resultados: 85.71%  
Cobertura ponderada: 87.50%

Pass: 21 · Fail: 3 · Warning: 4

O score considera somente pass/fail, com pesos por severidade. Warnings ficam fora do denominador e reduzem a cobertura. Um score alto com cobertura baixa não comprova segurança.

Host sintético para demonstração dos seis módulos; todos os dados são fictícios\.

**EXEMPLO SINTÉTICO: dados fictícios; não representa auditoria deste host.**

## [PASS] Shell interativo

ID: accounts\.shell\.nvg · Severidade: medium

Shell autorizado pela política\.

**Recomendação:** Revise o uso da conta; serviços que não precisam de login podem usar nologin\.

```json
{
  "user": "nvg",
  "uid": 1000,
  "shell": "/bin/bash"
}
```

## [PASS] Conta com UID 0

ID: accounts\.uid0\.root · Severidade: critical

Conta UID 0 autorizada\.

**Recomendação:** Mantenha apenas contas UID 0 explicitamente necessárias\.

```json
{
  "user": "root",
  "uid": 0,
  "shell": "/bin/bash"
}
```

## [PASS] Shell interativo

ID: accounts\.shell\.root · Severidade: medium

Shell autorizado pela política\.

**Recomendação:** Revise o uso da conta; serviços que não precisam de login podem usar nologin\.

```json
{
  "user": "root",
  "uid": 0,
  "shell": "/bin/bash"
}
```

## [FAIL] Credencial de nvg

ID: accounts\.password\.nvg · Severidade: high

Campo de senha vazio; acesso sem senha depende do PAM\.

**Recomendação:** Bloqueie senhas desnecessárias ou redefina a credencial conforme a política de autenticação do sistema\.

```json
{
  "user": "nvg"
}
```

## [PASS] Credencial de root

ID: accounts\.password\.root · Severidade: high

Autenticação por senha bloqueada; outros métodos de login não foram avaliados\.

**Recomendação:** Bloqueie senhas desnecessárias ou redefina a credencial conforme a política de autenticação do sistema\.

```json
{
  "user": "root"
}
```

## [WARNING] Força das senhas e políticas de autenticação

ID: accounts\.password\_strength · Severidade: medium

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise separadamente políticas de novas senhas, MFA quando aplicável e métodos de autenticação permitidos\.

**Limitação/revisão:** Força de senhas existentes não é inferível de hashes\. PAM, SSH, expiração e identidades NSS/LDAP não são avaliados nesta versão\.

## [PASS] fs\.protected\_hardlinks

ID: kernel\.fs\.protected\_hardlinks · Severidade: medium

Valor efetivo atende à política\. Restringe hardlinks para arquivos de outros usuários e reduz ataques por links em diretórios compartilhados\.

**Recomendação:** Configure fs\.protected\_hardlinks=1\.

```json
{
  "actual": 1,
  "accepted": [
    1
  ]
}
```

## [PASS] fs\.protected\_symlinks

ID: kernel\.fs\.protected\_symlinks · Severidade: medium

Valor efetivo atende à política\. Restringe o seguimento de symlinks em diretórios sticky graváveis por todos, mitigando substituição de arquivos\.

**Recomendação:** Configure fs\.protected\_symlinks=1\.

```json
{
  "actual": 1,
  "accepted": [
    1
  ]
}
```

## [PASS] fs\.suid\_dumpable

ID: kernel\.fs\.suid\_dumpable · Severidade: medium

Valor efetivo atende à política\. Desabilitar dumps convencionais de processos privilegiados reduz exposição de memória sensível\.

**Recomendação:** Configure fs\.suid\_dumpable=0 ou documente uma política alternativa de core dumps protegidos\.

```json
{
  "actual": 0,
  "accepted": [
    0
  ]
}
```

## [PASS] kernel\.dmesg\_restrict

ID: kernel\.kernel\.dmesg\_restrict · Severidade: medium

Valor efetivo atende à política\. Restringir logs do kernel reduz divulgação de endereços e detalhes internos a usuários sem privilégio\.

**Recomendação:** Configure kernel\.dmesg\_restrict=1 na política sysctl do sistema\.

```json
{
  "actual": 1,
  "accepted": [
    1
  ]
}
```

## [PASS] kernel\.kptr\_restrict

ID: kernel\.kernel\.kptr\_restrict · Severidade: medium

Valor efetivo atende à política\. Restringe a exposição de ponteiros do kernel nas interfaces que respeitam esta opção\.

**Recomendação:** Avalie o impacto em diagnóstico e configure kernel\.kptr\_restrict=2\.

```json
{
  "actual": 2,
  "accepted": [
    2
  ]
}
```

## [PASS] kernel\.randomize\_va\_space

ID: kernel\.kernel\.randomize\_va\_space · Severidade: high

Valor efetivo atende à política\. ASLR dificulta prever endereços de memória; valor 2 inclui randomização do heap onde suportado\.

**Recomendação:** Avalie compatibilidade e persista kernel\.randomize\_va\_space=2 em /etc/sysctl\.d/; confirme o valor efetivo após aplicar a política\.

```json
{
  "actual": 2,
  "accepted": [
    2
  ]
}
```

## [PASS] kernel\.yama\.ptrace\_scope

ID: kernel\.kernel\.yama\.ptrace\_scope · Severidade: medium

Valor efetivo atende à política\. Restrições de ptrace reduzem a inspeção de memória de outros processos; valores maiores têm custos diferentes para depuração\.

**Recomendação:** Escolha um nível compatível com o uso do NVG OS\. O nível 3 não pode ser relaxado sem reiniciar\.

```json
{
  "actual": 1,
  "accepted": [
    1,
    2,
    3
  ]
}
```

## [PASS] net\.ipv4\.conf\.all\.accept\_redirects

ID: kernel\.net\.ipv4\.conf\.all\.accept\_redirects · Severidade: medium

Valor efetivo atende à política\. Desabilitar redirects reduz mudanças de rota induzidas por mensagens ICMP; interfaces individuais também precisam de revisão\.

**Recomendação:** Configure accept\_redirects=0 para all, default e interfaces aplicáveis após avaliar a topologia\.

```json
{
  "actual": 0,
  "accepted": [
    0
  ]
}
```

## [FAIL] Socket autorizado pela whitelist

ID: network\.tcp\.0\.0\.0\.0\.8332 · Severidade: high

Escuta ausente da whitelist; exposição externa depende também de rotas e firewall\.

**Recomendação:** Identifique o serviço; restrinja seu bind/desative a escuta ou autorize explicitamente se necessária\.

```json
{
  "protocol": "tcp",
  "address": "0.0.0.0",
  "port": 8332
}
```

## [PASS] Socket autorizado pela whitelist

ID: network\.tcp\.127\.0\.0\.1\.9050 · Severidade: high

Escuta prevista na política\.

**Recomendação:** Mantenha a regra restrita ao endereço necessário\.

```json
{
  "protocol": "tcp",
  "address": "127.0.0.1",
  "port": 9050
}
```

## [FAIL] Proteção de caminho sensível

ID: permissions\.nostr\_demo · Severidade: critical

Bits de permissão excedem a máscara permitida\.

**Recomendação:** Revise proprietário, máscara de permissões e diretórios ancestrais; mantenha chaves acessíveis somente ao usuário necessário\.

```json
{
  "path": "/vault/nostr.key",
  "expected_uid": 1000,
  "max_mode": "0600",
  "mode": "0644",
  "uid": 1000,
  "gid": 1000
}
```

## [PASS] Privilégios de tor\.service

ID: services\.tor\.service · Severidade: high

Processo principal sem UID root\.

**Recomendação:** Mantenha o menor privilégio necessário e revise exceções root periodicamente\.

```json
{
  "unit": "tor.service",
  "main_pid": 123,
  "effective_uid": 974
}
```

## [WARNING] Cobertura dos processos de serviço

ID: services\.scope · Severidade: medium

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Complemente a revisão com processos filhos/cgroups e serviços iniciados fora do systemd\.

**Limitação/revisão:** Somente MainPID de unidades systemd running no gerenciador do sistema; filhos, serviços de usuário, contêineres e daemons externos não são enumerados\.

## [PASS] Serviço Tor ativo

ID: tor\.service · Severidade: high

Unidade ativa com processo principal\.

**Recomendação:** Confirme a unidade Tor usada pelo NVG OS e examine seu estado e logs locais\.

```json
{
  "unit": "tor.service",
  "load_state": "loaded",
  "active_state": "active"
}
```

## [PASS] Bind de socksport

ID: tor\.socksport · Severidade: high

Endpoints declarados restritos a loopback ou desativados\.

**Recomendação:** Restrinja endpoints de cliente/controle ao loopback; este perfil é para um host cliente NVG OS\.

```json
{
  "endpoints": [
    {
      "address": "127.0.0.1",
      "port": 9050,
      "loopback": true
    }
  ],
  "source": "torrc declarado; n\u00e3o \u00e9 configura\u00e7\u00e3o efetiva do processo"
}
```

## [PASS] Bind de dnsport

ID: tor\.dnsport · Severidade: high

Endpoints declarados restritos a loopback ou desativados\.

**Recomendação:** Restrinja endpoints de cliente/controle ao loopback; este perfil é para um host cliente NVG OS\.

```json
{
  "endpoints": [],
  "source": "torrc declarado; n\u00e3o \u00e9 configura\u00e7\u00e3o efetiva do processo"
}
```

## [PASS] Bind de transport

ID: tor\.transport · Severidade: high

Endpoints declarados restritos a loopback ou desativados\.

**Recomendação:** Restrinja endpoints de cliente/controle ao loopback; este perfil é para um host cliente NVG OS\.

```json
{
  "endpoints": [],
  "source": "torrc declarado; n\u00e3o \u00e9 configura\u00e7\u00e3o efetiva do processo"
}
```

## [PASS] Bind de controlport

ID: tor\.controlport · Severidade: high

Endpoints declarados restritos a loopback ou desativados\.

**Recomendação:** Restrinja endpoints de cliente/controle ao loopback; este perfil é para um host cliente NVG OS\.

```json
{
  "endpoints": [],
  "source": "torrc declarado; n\u00e3o \u00e9 configura\u00e7\u00e3o efetiva do processo"
}
```

## [PASS] Proteção contra resolução DNS prévia via SOCKS

ID: tor\.safe\_socks · Severidade: high

SafeSocks habilitado no arquivo\.

**Recomendação:** Defina SafeSocks 1 e configure clientes para enviar nomes ao proxy \(por exemplo, socks5h\)\.

## [PASS] Resolvedores DNS declarados

ID: tor\.dns\_resolvers · Severidade: high

Endereços nameserver correspondem à política configurada\.

**Recomendação:** Verifique a cadeia do resolvedor local, o uso de DNS pelo proxy e as regras de saída IPv4/IPv6\.

```json
{
  "nameservers": [
    "127.0.0.1"
  ],
  "unexpected_nameservers": []
}
```

## [WARNING] Ausência de vazamento DNS

ID: tor\.dns\_assurance · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise o encaminhamento do resolvedor e a política de saída; configure aplicações para resolução pelo proxy\. DNSPort sozinho não força o tráfego a passar pelo Tor\.

**Limitação/revisão:** Não comprovável por estes checks passivos: upstream do stub, firewall, DNS de aplicativos e IPv6 não foram validados de ponta a ponta\.

## [WARNING] Correspondência com o Tor em execução

ID: tor\.runtime\_config · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Confirme os arquivos e argumentos da unidade e a configuração efetiva do Tor antes de interpretar os resultados como estado em execução\.

**Limitação/revisão:** Auditoria do torrc selecionado; defaults\-torrc, opções de linha de comando, configuração não recarregada e bootstrap não são verificados\.

