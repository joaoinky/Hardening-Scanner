# Auditoria de hardening — NVG OS

Perfil: installed  
Data UTC: 2026\-09\-13T12:00:00\+00:00

**Score de conformidade: 100.00/100**  
Cobertura por resultados: 25.00%  
Cobertura ponderada: 43.48%

Pass: 1 · Fail: 0 · Warning: 3

O score considera somente pass/fail, com pesos por severidade. Warnings ficam fora do denominador e reduzem a cobertura. Um score alto com cobertura baixa não comprova segurança.

Dados sintéticos de demonstração; nenhum segredo do usuário\.

**Cobertura criptográfica de pacotes: total instalado desconhecido; verificação não concluída ou não executada.**

**Falhas critical: 0 · Score equilibrado por domínio: 100.0**

Cada domínio contribui igualmente para esta média; a quantidade de pacotes não aumenta o peso do domínio. Ambos os scores excluem resultados inconclusivos.

| Domínio | Score | Cobertura ponderada | Fail | Warning |
| --- | ---: | ---: | ---: | ---: |
| firewall | 100.0 | 100.0% | 0 | 0 |
| storage | None | 0.0% | 0 | 3 |

Ambiente esperado: installed · Rede esperada: base · Política: nos\-1\.2\.1\-v1

**EXEMPLO SINTÉTICO: dados fictícios; não representa auditoria deste host.**

## [PASS] Conformidade com o modo de rede solicitado

ID: firewall\.nos\_mode · Severidade: critical

Observação nova confrontada com a política solicitada e as referências locais do nOS\.

**Recomendação:** Revise o modo esperado, as referências distribuídas e o estado do kernel; consulta não comprova anonimato ou isolamento físico\.

```json
{
  "state": "verified",
  "expected_mode": "base",
  "observed_at": "2026-09-13T03:38:56.059222+00:00",
  "reference_sha256": "c204bef1f593c8f5d3ba2dd65897b4828d6e767855f1f975820fbd34c23489d2",
  "reasons": [
    "nft: permiss\u00e3o insuficiente"
  ]
}
```

## [WARNING] Montagens efetivas

ID: storage\.mounts · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Comando não disponível na fixture

## [WARNING] Persistência do swap

ID: storage\.swap · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Inventário de swap indisponível ou inválido\.

## [WARNING] Política journald

ID: storage\.journal · Severidade: medium

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Configuração composta indisponível ou construção não interpretada\.

