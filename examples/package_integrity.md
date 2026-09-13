# Auditoria de hardening — NVG OS

Perfil: installed  
Data UTC: 2026\-09\-13T12:00:00\+00:00

**Score de conformidade: 100.00/100**  
Cobertura por resultados: 57.14%  
Cobertura ponderada: 74.07%

Pass: 4 · Fail: 0 · Warning: 3

O score considera somente pass/fail, com pesos por severidade. Warnings ficam fora do denominador e reduzem a cobertura. Um score alto com cobertura baixa não comprova segurança.

Dados sintéticos de demonstração; nenhum segredo do usuário\.

**Pacotes verificados criptograficamente: 1 de 2 (50.00%). Não verificados: 1.**

Selecionados: 2 · Examinados: 2 · Tentativas: 1 · Inconclusivos entre examinados: 1

Assinaturas válidas: 1 · Inválidas: 0 · Válidas com confiança suficiente: 1

Verificado significa resultado criptográfico conclusivo (válido ou inválido), não aprovação. A cobertura é dos artefatos em cache, não dos bytes instalados. Tentativa, cache ausente e chave pública ausente não contam como verificação.

**Falhas critical: 0 · Score equilibrado por domínio: 100.0**

Cada domínio contribui igualmente para esta média; a quantidade de pacotes não aumenta o peso do domínio. Ambos os scores excluem resultados inconclusivos.

| Domínio | Score | Cobertura ponderada | Fail | Warning |
| --- | ---: | ---: | ---: | ---: |
| package\_integrity | 100.0 | 74.07% | 0 | 3 |

**EXEMPLO SINTÉTICO: dados fictícios; não representa auditoria deste host.**

## [PASS] Política de assinatura pacman

ID: package\_integrity\.policy\.global · Severidade: high

Assinaturas obrigatórias com TrustedOnly\.

**Recomendação:** Revise SigLevel e LocalFileSigLevel, incluindo políticas dos repositórios NVG OS\.

## [PASS] Política de assinatura pacman

ID: package\_integrity\.policy\.local\_file · Severidade: high

Assinaturas obrigatórias com TrustedOnly\.

**Recomendação:** Revise SigLevel e LocalFileSigLevel, incluindo políticas dos repositórios NVG OS\.

## [PASS] Política de assinatura pacman

ID: package\_integrity\.policy\.repo\.core · Severidade: high

Assinaturas obrigatórias com TrustedOnly\.

**Recomendação:** Revise SigLevel e LocalFileSigLevel, incluindo políticas dos repositórios NVG OS\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.foreign · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [PASS] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.bitcoin · Severidade: high

Assinatura criptográfica válida e confiança suficiente no keyring local\.

**Recomendação:** Use artefatos assinados por signatários confiáveis; revise o keyring local e sua atualização por procedimento separado\.

```json
{
  "package": "bitcoin",
  "version": "1.0-1",
  "scope": "arquivo no cache; n\u00e3o \u00e9 integridade dos arquivos instalados"
}
```

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.foreign · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Limites de integridade local

ID: package\_integrity\.scope · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Assinaturas do cache não comprovam os bytes atualmente instalados nem a procedência histórica\. Bases/keyring podem estar desatualizados; sem consulta de revogação online\. Confiança só é avaliada para signatários verificáveis\.

