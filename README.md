# S.C.A.C.

## Sistema de Controle de Acesso Compartilhado

O S.C.A.C. é uma solução para gerenciamento de computadores compartilhados em ambientes corporativos.

Seu objetivo é permitir que equipes de TI definam, distribuam e mantenham políticas de utilização de forma centralizada, reduzindo tarefas manuais e mantendo os ambientes consistentes entre diferentes usuários e períodos de utilização.

O S.C.A.C. permite definir **políticas compartilhadas** que representam como determinado ambiente deve funcionar.

Essas políticas podem ser aplicadas a múltiplos computadores, permitindo que a equipe de TI gerencie o ambiente de forma centralizada.

A abordagem é orientada ao **ambiente compartilhado**, e não somente ao usuário individual.

Isso permite combinar gerenciamento de acesso, configuração, utilização e restauração em um único fluxo.

## Instalação

Requisitos:

* CMake;
* compilador compatível com C11+, recomenda-se o GCC;

Para compilar:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
```

```bash
bash scripts/build.sh
```

## Uso

O binário do administrador permite descobrir computadores, enviar políticas e consultar o estado e logs dos ambientes gerenciados

```text
./build/admin/labadmin discover

./build/admin/labadmin push <host> policies/<policy>.json

./build/admin/labadmin status <host>
```

