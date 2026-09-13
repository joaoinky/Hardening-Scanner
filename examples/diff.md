# Diff de hardening — NVG OS

**0 novos fails · 1 fails resolvidos**

Score: 82.14 → 91.07 (delta: 8.93).

Novos warnings: 0 · Warnings resolvidos: 0 · Adicionados: 0 · Removidos: 0

**EXEMPLO SINTÉTICO: nenhuma auditoria real deste host.**

coverage_percent: 85.71 → 85.71 (delta: 0.0).

weighted_coverage_percent: 87.5 → 87.5 (delta: 0.0).

Pacotes — total\_installed: None → None (delta: None).

Pacotes — selected: 0 → 0 (delta: 0).

Pacotes — examined: 0 → 0 (delta: 0).

Pacotes — cryptographically\_verified: 0 → 0 (delta: 0).

Pacotes — valid\_signatures: 0 → 0 (delta: 0).

Pacotes — invalid\_signatures: 0 → 0 (delta: 0).

Pacotes — trusted\_valid\_signatures: 0 → 0 (delta: 0).

Pacotes — not\_verified: None → None (delta: None).

Pacotes — coverage\_percent: None → None (delta: None).

Score equilibrado por domínio: 71.8 → 88.46 (delta: 16.66).

Removido significa ausente do relatório, não recurso corrigido. Política/inventário podem mudar sem identificação nos relatórios legados. Nenhum conteúdo de evidência é reproduzido.

| ID | Presença | Transição | Antes | Depois |
| --- | --- | --- | --- | --- |
| accounts\.password\.nvg | both | unchanged | fail | fail |
| accounts\.password\.root | both | unchanged | pass | pass |
| accounts\.password\_strength | both | unchanged | warning | warning |
| accounts\.shell\.nvg | both | unchanged | pass | pass |
| accounts\.shell\.root | both | unchanged | pass | pass |
| accounts\.uid0\.root | both | unchanged | pass | pass |
| kernel\.fs\.protected\_hardlinks | both | unchanged | pass | pass |
| kernel\.fs\.protected\_symlinks | both | unchanged | pass | pass |
| kernel\.fs\.suid\_dumpable | both | unchanged | pass | pass |
| kernel\.kernel\.dmesg\_restrict | both | unchanged | pass | pass |
| kernel\.kernel\.kptr\_restrict | both | unchanged | pass | pass |
| kernel\.kernel\.randomize\_va\_space | both | unchanged | pass | pass |
| kernel\.kernel\.yama\.ptrace\_scope | both | unchanged | pass | pass |
| kernel\.net\.ipv4\.conf\.all\.accept\_redirects | both | unchanged | pass | pass |
| network\.tcp\.0\.0\.0\.0\.8332 | both | unchanged | fail | fail |
| network\.tcp\.127\.0\.0\.1\.9050 | both | unchanged | pass | pass |
| permissions\.nostr\_demo | both | resolved_fail | fail | pass |
| services\.scope | both | unchanged | warning | warning |
| services\.tor\.service | both | unchanged | pass | pass |
| tor\.controlport | both | unchanged | pass | pass |
| tor\.dns\_assurance | both | unchanged | warning | warning |
| tor\.dns\_resolvers | both | unchanged | pass | pass |
| tor\.dnsport | both | unchanged | pass | pass |
| tor\.runtime\_config | both | unchanged | warning | warning |
| tor\.safe\_socks | both | unchanged | pass | pass |
| tor\.service | both | unchanged | pass | pass |
| tor\.socksport | both | unchanged | pass | pass |
| tor\.transport | both | unchanged | pass | pass |
