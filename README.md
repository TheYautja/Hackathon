# S.C.A.C

Sistema de controle de acesso compartilhado

## Arquitetura

```
PC Administrador (labadmin)          PC Cliente (labagent)
        |                                    |
        |  UDP 7801 — discovery              |
        |  TCP 7800 — comandos assinados       |
        +------------------------------------+
```

| Componente | Descrição |
|---|---|
| `labagent` | Serviço/daemon local: políticas, enforcement, reset, IPC |
| `labadmin` | CLI do administrador: discovery, push, status, switch, reset |
| `policies/` | Perfis JSON (Aluno, Programação, Redes) |
| `keys/shared.key` | Chave HMAC compartilhada (32 bytes) |

## Requisitos

- Windows 10/11 (MVP prioritário)
- CMake 3.16+
- Visual Studio Build Tools ou MSVC
- PowerShell

## Build

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
```

Gera:
- `build/agent/Release/labagent.exe`
- `build/admin/Release/labadmin.exe`

## Uso rápido (demo)

**Terminal 1 — Agente (preferencialmente como Administrador):**

```powershell
.\build\agent\Release\labagent.exe --key keys\shared.key
```

**Terminal 2 — Administrador:**

```powershell
# Descobrir agentes na LAN
.\build\admin\Release\labadmin.exe discover

# Enviar política
.\build\admin\Release\labadmin.exe push DESKTOP-ABC policies\default.json

# Ver status
.\build\admin\Release\labadmin.exe status DESKTOP-ABC

# Trocar perfil manualmente
.\build\admin\Release\labadmin.exe switch DESKTOP-ABC Programacao

# Restaurar ambiente (baseline)
.\build\admin\Release\labadmin.exe reset DESKTOP-ABC
```

**Fallback sem discovery:**

```powershell
.\build\admin\Release\labadmin.exe add lab-pc-01 192.168.1.50
```

## Console gráfico de teste

Com os binários compilados, abra a interface visual com:

```powershell
python scripts\gui.py
```

(exclusivo do windows)

A GUI usa o `labadmin.exe` existente para descobrir agentes, consultar status, enviar a política, trocar perfil e disparar reset. O botão **Iniciar agente local** facilita o teste em uma única máquina.

## Funcionalidades implementadas

- Políticas assinadas (HMAC-SHA256) com cache local em `C:\ProgramData\LabAgent\`
- Perfis dinâmicos com apps bloqueados/permitidos
- Alternância automática por horário (schedules)
- Discovery UDP broadcast + TCP assinado
- Monitor de processos bloqueados (kill a cada 2s)
- Reset de Desktop/Downloads via robocopy + baseline
- Audit log em `C:\ProgramData\LabAgent\audit.log`
- IPC via Named Pipe (`\\.\pipe\labagent`)

## Estrutura do projeto

```
├── agent/          # Agente local (C)
├── admin/          # CLI administrador (C)
├── shared/         # Protocolo, políticas, crypto
├── policies/       # Perfis JSON de exemplo
├── scripts/        # build, genkeys, demo
└── keys/           # Chave compartilhada (gerada localmente)
```

## Segurança

- Políticas seladas: hash SHA-256 + assinatura HMAC
- Mensagens LAN com HMAC por pacote + seq anti-replay básico
- IPC autenticado via mesma chave
- Dados em `C:\ProgramData\LabAgent\` (requer admin para instalação)

## Limitações do MVP (hackathon)

- Agente roda como console app (não Windows Service instalado)
- Enforcement por kill de processos (não AppLocker/GPO)
- Reset parcial (Desktop/Downloads), sem snapshot de disco
- Usuário com privilégios de admin local pode desabilitar o agente

## Licença

Projeto acadêmico — Hackathon.
