# Auditoria de hardening — NVG OS

Perfil: installed  
Data UTC: 2026\-09\-13T12:00:00\+00:00

**Score de conformidade: 60.00/100**  
Cobertura por resultados: 100.00%  
Cobertura ponderada: 100.00%

Pass: 3 · Fail: 2 · Warning: 0

O score considera somente pass/fail, com pesos por severidade. Warnings ficam fora do denominador e reduzem a cobertura. Um score alto com cobertura baixa não comprova segurança.

Dados sintéticos de demonstração; nenhum segredo do usuário\.

**Cobertura criptográfica de pacotes: total instalado desconhecido; verificação não concluída ou não executada.**

**Falhas critical: 0 · Score equilibrado por domínio: 60.0**

Cada domínio contribui igualmente para esta média; a quantidade de pacotes não aumenta o peso do domínio. Ambos os scores excluem resultados inconclusivos.

| Domínio | Score | Cobertura ponderada | Fail | Warning |
| --- | ---: | ---: | ---: | ---: |
| firewall | 60.0 | 100.0% | 2 | 0 |

**EXEMPLO SINTÉTICO: dados fictícios; não representa auditoria deste host.**

## [PASS] Política de entrada

ID: firewall\.ip\.default · Severidade: high

Política de descarte/regra terminal ou exceção explícita identificada\.

**Recomendação:** Prefira policy drop ou regra terminal de descarte/reject; revise as exceções explícitas\.

```json
{
  "family": "ip",
  "chain_policy": "drop",
  "fallback_verdict": "accept",
  "justified_accept": false
}
```

## [FAIL] Permissão de entrada versus whitelist

ID: firewall\.ip\.allow\.0 · Severidade: high

Regra permite tráfego além da whitelist, mesmo que não haja listener agora\.

**Recomendação:** Restrinja protocolo, porta e destino ao necessário\.

```json
{
  "family": "ip",
  "rule_index": 0
}
```

## [PASS] Cobertura do socket

ID: firewall\.ip\.socket\.tcp\.127\.0\.0\.1\.9050 · Severidade: high

Socket bloqueado ou permitido explicitamente conforme a whitelist no modelo input\.

**Recomendação:** Revise o bind e a regra de entrada correspondente\.

```json
{
  "protocol": "tcp",
  "address": "127.0.0.1",
  "port": 9050,
  "verdict": "accept",
  "source": "rule"
}
```

## [PASS] Política de entrada

ID: firewall\.ip6\.default · Severidade: high

Política de descarte/regra terminal ou exceção explícita identificada\.

**Recomendação:** Prefira policy drop ou regra terminal de descarte/reject; revise as exceções explícitas\.

```json
{
  "family": "ip6",
  "chain_policy": "drop",
  "fallback_verdict": "accept",
  "justified_accept": false
}
```

## [FAIL] Permissão de entrada versus whitelist

ID: firewall\.ip6\.allow\.0 · Severidade: high

Regra permite tráfego além da whitelist, mesmo que não haja listener agora\.

**Recomendação:** Restrinja protocolo, porta e destino ao necessário\.

```json
{
  "family": "ip6",
  "rule_index": 0
}
```

