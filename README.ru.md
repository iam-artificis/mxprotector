# MxProtector

Пакет защиты бинарных файлов на C++23 для Windows PE x64.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/iam-artificis/mxprotector/actions/workflows/ci.yml/badge.svg)](https://github.com/iam-artificis/mxprotector/actions/workflows/ci.yml)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-informational.svg)](https://en.cppreference.com/w/cpp/23)

**[English README](README.md)**

## Что он делает

MxProtector прогоняет Windows PE x64 бинарник через фиксированный
pipeline защиты: **mutation -> obfuscation -> virtualization -> guard
-> CFF -> string protection -> packer**. Mixed boolean-arithmetic
(MBA) rewriting включено по умолчанию в mutation и CFF transitions.

Аннотации в исходном коде позволяют подключить к отдельным регионам и
константам усиленные трансформации через небольшой SDK:
`MX_VM_BEGIN` / `MX_VM_END` и `MX_GUARD_BEGIN` / `MX_GUARD_END`
размечают диапазоны для виртуальной машины и VEH-dispatched guard'а, а
`MX_STR` / `MX_WSTR` / `MX_CONST` шифруют строковые литералы и
константные пулы.

Windows PE x64 (`.exe` и `.dll`) полностью поддерживается сегодня. ELF
и ARM64 — в roadmap и гейтируются на уровне проходов, так что
несовместимые входы корректно отваливаются, а не крашатся.

## Статус

Исследовательский / экспериментальный. Не production-ready.

- `.exe` x64 — полный pipeline, 15/15 strong stress + полный unit-test suite.
- `.dll` x64 — полный pipeline включая DLL packer и VEH из TLS callback.
- `.sys` x64 — не протестировано (блокирует test-signing); build-time coverage есть.
- ELF, ARM64, UEFI — в roadmap. См. [`ROADMAP.md`](ROADMAP.md).

## Требования

- CMake >= 3.20
- C++23-компилятор: MSVC 2022, GCC 13+ или Clang 16+
- Git submodules (подтягивает Zydis)
- Python 3.11+ для measurement suite в [`mcp/`](mcp/) (опционально)

## Сборка

Клонировать с подмодулями:

```bash
git clone https://github.com/iam-artificis/mxprotector.git
cd mxprotector
git submodule update --init --recursive
```

Сконфигурировать и собрать протектор:

```bash
cmake -S . -B build -DMXPROTECTOR_BUILD_TESTS=ON
cmake --build build --config Release --target mxprotector_builder
```

Прогнать unit-тесты (опционально, но рекомендуется):

```bash
ctest --test-dir build --output-on-failure
```

## Использование

Защитить бинарник одной командой:

```bash
./build/src/builder/Release/mxprotector_builder -i input.exe -o output.exe -l strong
```

Флаги:

- `-i <путь>` — входной PE (`.exe` или `.dll`).
- `-o <путь>` — выходной PE.
- `-l <уровень>` — уровень защиты. Один из:
  - `minimal`   — только mutation.
  - `standard`  — mutation + obfuscation + CFF + strings.
  - `strong`    — добавляет virtualization, guard и packer. Дефолтная цель для CI stress.
  - `maximum`   — strong с самыми агрессивными настройками.
- Pass gates (opt-out): `--no-mutation`, `--no-obfuscation`, `--no-vm`,
  `--no-guard`, `--no-cff`, `--no-strings`, `--no-packer`,
  `--no-mba-substitution`.

Полная поверхность CLI заморожена; см. [`STABILITY.md`](STABILITY.md).

## SDK

SDK — это header-only набор макросов, подключаемый защищаемым
исходником. Он с контрактно-замороженной поверхностью: обновления
протектора не должны требовать от пользователей менять их исходный
код. Marker ID, magic value, кодировка и имена CLI — всё определено в
[`STABILITY.md`](STABILITY.md).

## Measurement suite

`mcp/` содержит **mx-mcp** — Python MCP-сервер, который измеряет
силу защиты MxProtector против современных reversing-тулз (angr, IDA
microcode / d810, unicorn, unipacker, pe-sieve, BinDiff, Frida,
msynth, SiMBA). Установка и использование описаны в
[`mcp/README.md`](mcp/README.md); таксономия и phase plan лежат в
[`MCP.md`](MCP.md).

## Документация

- [`STABILITY.md`](STABILITY.md) — контракт стабильности SDK-маркеров и CLI.
- [`MCP.md`](MCP.md) — таксономия measurement и phase plan.
- [`ROADMAP.md`](ROADMAP.md) — планируемые фичи и работа над driver'ами.
- [`FUTURE.md`](FUTURE.md) — post-MVP backlog.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — как предлагать изменения.
- [`SECURITY.md`](SECURITY.md) — репортинг уязвимостей.
- [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) — для чего этот проект и для чего — нет.

## Допустимое использование

Это dual-use инструмент. Прочитайте
[`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) перед использованием.

## Лицензия

MIT — см. [`LICENSE`](LICENSE). Third-party компоненты и их лицензии
перечислены в [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

## Контакт

Баг-репорты и запросы фич: откройте issue на
[GitHub Issues](https://github.com/iam-artificis/mxprotector/issues).
