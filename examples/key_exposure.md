# Auditoria de hardening — NVG OS

Perfil: installed  
Data UTC: 2026\-09\-13T12:00:00\+00:00

**Score de conformidade: 0.00/100**  
Cobertura por resultados: 100.00%  
Cobertura ponderada: 100.00%

Pass: 0 · Fail: 1 · Warning: 0

O score considera somente pass/fail, com pesos por severidade. Warnings ficam fora do denominador e reduzem a cobertura. Um score alto com cobertura baixa não comprova segurança.

Dados sintéticos de demonstração; nenhum segredo do usuário\.

**Cobertura criptográfica de pacotes: total instalado desconhecido; verificação não concluída ou não executada.**

**Falhas critical: 1 · Score equilibrado por domínio: 0.0**

Cada domínio contribui igualmente para esta média; a quantidade de pacotes não aumenta o peso do domínio. Ambos os scores excluem resultados inconclusivos.

| Domínio | Score | Cobertura ponderada | Fail | Warning |
| --- | ---: | ---: | ---: | ---: |
| key\_exposure | 0.0 | 100.0% | 1 | 0 |

**EXEMPLO SINTÉTICO: dados fictícios; não representa auditoria deste host.**

## [FAIL] Material de chave em texto plano

ID: key\_exposure\.history\.file\./home/nvg/\.bash\_history · Severidade: critical

Padrão de chave/mnemônico validado ou credencial bunker reconhecida no arquivo; não comprova uso, autorização ou saldo\.

**Recomendação:** Revise a exposição local em ambiente confiável e a necessidade de substituir a chave/carteira; o scanner não remove dados nem movimenta fundos\.

```json
{
  "path": "/home/nvg/.bash_history",
  "occurrences": {
    "nsec": 1,
    "wif": 1,
    "bip39": 1
  }
}
```

