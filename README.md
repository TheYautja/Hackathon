# S.C.A.C.

## Sistema de Controle de Acesso Compartilhado

O S.C.A.C. é uma solução para gerenciamento de computadores compartilhados em ambientes corporativos.

Seu objetivo é permitir que equipes de TI definam, distribuam e mantenham políticas de utilização de forma centralizada, reduzindo tarefas manuais e mantendo os ambientes consistentes entre diferentes usuários e períodos de utilização.

## O problema

Computadores compartilhados são utilizados por diferentes pessoas, equipes e turnos. Sem um gerenciamento adequado, alterações realizadas durante uma utilização podem afetar o próximo usuário e aumentar o trabalho da equipe responsável pela infraestrutura.

Entre os problemas mais comuns estão:

* configurações inconsistentes;
* utilização de aplicações inadequadas;
* alterações não autorizadas;
* necessidade de reconfiguração frequente;
* tempo gasto na manutenção das estações;
* dificuldade para restaurar o ambiente entre utilizações.

## A proposta

O S.C.A.C. permite definir **políticas compartilhadas** que representam como determinado ambiente deve funcionar.

Essas políticas podem ser aplicadas a múltiplos computadores, permitindo que a equipe de TI gerencie o ambiente de forma centralizada.

A abordagem é orientada ao **ambiente compartilhado**, e não somente ao usuário individual.

Isso permite combinar gerenciamento de acesso, configuração, utilização e restauração em um único fluxo.

## Principais recursos

* Gerenciamento centralizado de computadores;
* Políticas compartilhadas;
* Perfis para diferentes ambientes e funções;
* Controle de aplicações;
* Agendamento de políticas;
* Restauração de ambientes;
* Registro de atividades;
* Administração remota.

## Casos de uso

O S.C.A.C. pode ser utilizado em ambientes como:

* estações compartilhadas;
* salas de treinamento;
* operações por turnos;
* ambientes de atendimento;
* laboratórios corporativos;
* espaços de trabalho temporários;
* computadores utilizados por diferentes equipes.

## Por que políticas compartilhadas?

Soluções tradicionais de gerenciamento geralmente são centradas no usuário, no dispositivo ou em uma tarefa específica.

O S.C.A.C. utiliza uma abordagem baseada no **estado desejado do ambiente**.

Em vez de configurar cada computador individualmente, a equipe de TI pode definir uma política e aplicá-la às máquinas que pertencem àquele ambiente.

Isso facilita mudanças de configuração e reduz operações repetitivas.

## Instalação

O projeto atualmente está em desenvolvimento, com foco inicial em ambientes Windows.

Requisitos:

* Windows 10 ou superior;
* CMake;
* compilador compatível com o projeto;
* PowerShell.

Para compilar:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
```

## Utilização

Após a compilação, o administrador pode utilizar o cliente de gerenciamento para:

```text
Descobrir computadores
Enviar políticas
Consultar status
Alterar perfis
Restaurar ambientes
```

Exemplo:

```powershell
.\build\admin\Release\labadmin.exe discover
```

```powershell
.\build\admin\Release\labadmin.exe push DESKTOP-ABC policies\default.json
```

```powershell
.\build\admin\Release\labadmin.exe status DESKTOP-ABC
```

## Projeto

O S.C.A.C. é desenvolvido como um projeto experimental para explorar uma abordagem mais simples e centralizada para o gerenciamento de ambientes computacionais compartilhados.

O projeto encontra-se em estágio de MVP e está sujeito a mudanças conforme a validação da proposta e evolução do produto.

## Contribuição

Contribuições, sugestões e discussões são bem-vindas.

Para contribuir:

1. Faça um fork do projeto.
2. Crie uma branch para sua alteração.
3. Implemente e teste suas mudanças.
4. Abra um Pull Request descrevendo a alteração.

## Licença

Projeto acadêmico desenvolvido para hackathon.

