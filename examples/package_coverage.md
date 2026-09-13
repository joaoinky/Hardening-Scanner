# Auditoria de hardening — NVG OS

Perfil: installed  
Data UTC: 2026\-09\-13T12:00:00\+00:00

**Score de conformidade: 100.00/100**  
Cobertura por resultados: 1.53%  
Cobertura ponderada: 2.53%

Pass: 4 · Fail: 0 · Warning: 258

O score considera somente pass/fail, com pesos por severidade. Warnings ficam fora do denominador e reduzem a cobertura. Um score alto com cobertura baixa não comprova segurança.

Dados sintéticos de demonstração; nenhum segredo do usuário\.

**Pacotes verificados criptograficamente: 1 de 130 (0.77%). Não verificados: 129.**

Selecionados: 128 · Examinados: 128 · Tentativas: 1 · Inconclusivos entre examinados: 127

Assinaturas válidas: 1 · Inválidas: 0 · Válidas com confiança suficiente: 1

Verificado significa resultado criptográfico conclusivo (válido ou inválido), não aprovação. A cobertura é dos artefatos em cache, não dos bytes instalados. Tentativa, cache ausente e chave pública ausente não contam como verificação.

**Falhas critical: 0 · Score equilibrado por domínio: 100.0**

Cada domínio contribui igualmente para esta média; a quantidade de pacotes não aumenta o peso do domínio. Ambos os scores excluem resultados inconclusivos.

| Domínio | Score | Cobertura ponderada | Fail | Warning |
| --- | ---: | ---: | ---: | ---: |
| package\_integrity | 100.0 | 2.53% | 0 | 258 |

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

## [WARNING] Limite de pacotes

ID: package\_integrity\.budget · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Inventário maior que max\_packages; verificação criptográfica parcial\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg000 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg001 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg002 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg003 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg004 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg005 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg006 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg007 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg008 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg009 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg010 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg011 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg012 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg013 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg014 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg015 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg016 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg017 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg018 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg019 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg020 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg021 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg022 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg023 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg024 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg025 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg026 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg027 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg028 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg029 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg030 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg031 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg032 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg033 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg034 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg035 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg036 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg037 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg038 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg039 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg040 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg041 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg042 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg043 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg044 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg045 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg046 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg047 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg048 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg049 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg050 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg051 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg052 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg053 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg054 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg055 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg056 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg057 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg058 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg059 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg060 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg061 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg062 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg063 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg064 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg065 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg066 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg067 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg068 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg069 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg070 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg071 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg072 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg073 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg074 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg075 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg076 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg077 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg078 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg079 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg080 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg081 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg082 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg083 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg084 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg085 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg086 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg087 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg088 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg089 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg090 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg091 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg092 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg093 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg094 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg095 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg096 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg097 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg098 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg099 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg100 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg101 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg102 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg103 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg104 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg105 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg106 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg107 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg108 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg109 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg110 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg111 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg112 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg113 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg114 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg115 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg116 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg117 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg118 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg119 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg120 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg121 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg122 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg123 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg124 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg125 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg126 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg127 · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via \-U ou ausência de assinatura\.

## [WARNING] Pacote fora das bases configuradas

ID: package\_integrity\.foreign\.pkg128 · Severidade: info

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

ID: package\_integrity\.signature\.pkg000 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg001 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg002 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg003 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg004 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg005 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg006 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg007 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg008 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg009 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg010 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg011 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg012 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg013 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg014 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg015 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg016 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg017 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg018 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg019 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg020 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg021 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg022 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg023 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg024 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg025 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg026 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg027 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg028 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg029 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg030 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg031 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg032 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg033 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg034 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg035 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg036 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg037 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg038 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg039 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg040 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg041 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg042 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg043 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg044 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg045 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg046 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg047 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg048 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg049 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg050 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg051 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg052 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg053 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg054 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg055 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg056 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg057 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg058 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg059 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg060 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg061 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg062 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg063 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg064 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg065 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg066 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg067 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg068 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg069 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg070 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg071 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg072 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg073 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg074 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg075 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg076 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg077 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg078 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg079 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg080 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg081 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg082 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg083 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg084 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg085 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg086 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg087 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg088 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg089 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg090 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg091 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg092 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg093 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg094 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg095 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg096 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg097 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg098 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg099 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg100 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg101 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg102 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg103 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg104 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg105 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg106 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg107 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg108 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg109 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg110 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg111 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg112 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg113 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg114 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg115 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg116 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg117 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg118 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg119 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg120 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg121 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg122 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg123 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg124 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg125 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Assinatura do pacote e confiança

ID: package\_integrity\.signature\.pkg126 · Severidade: high

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica

## [WARNING] Limites de integridade local

ID: package\_integrity\.scope · Severidade: info

Verificação inconclusiva ou dependente de revisão contextual\.

**Recomendação:** Revise a evidência e execute novamente com os pré\-requisitos disponíveis\.

**Limitação/revisão:** Assinaturas do cache não comprovam os bytes atualmente instalados nem a procedência histórica\. Bases/keyring podem estar desatualizados; sem consulta de revogação online\. Confiança só é avaliada para signatários verificáveis\.

