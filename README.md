# UwU_Driver Made By @Br0kenFox

Hypervisor-based Windows 11 Test Mode Patch (EPT Hooking) AKA Ring 0 (Driver) BattleEye Bypass 

---

## Описание

Kernel-mode KMDF-драйвер для Windows x64. Устанавливает 14-байтовый inline-хук на экспортируемую функцию `NtQuerySystemInformation` (класс 103 — `SystemCodeIntegrityInformation`), очищает биты `TESTSIGN`/UMCI в возвращаемом значении `CodeIntegrityOptions` и обнуляет ключ `TestSigning` в реестре (`HKLM\SYSTEM\CurrentControlSet\Control\CI\Config`). Используется в CTF-задачах, которые проверяют состояние Code Integrity.

---

## Зависимости для сборки

| Компонент | Версия / примечание |
|-----------|---------------------|
| **Visual Studio** | 2022 (toolset v143) |
| **Windows Driver Kit (WDK)** | 10.0, совпадающий с версией VS — [скачать](https://learn.microsoft.com/ru-ru/windows-hardware/drivers/download-the-wdk) |
| **Windows SDK** | Включён в VS; версия должна совпадать с WDK |
| **Целевая платформа** | Windows 10 / 11 — x64 или ARM64 |

> WDK встраивается в Visual Studio как тулсет **WindowsKernelModeDriver10.0**. Оба компонента должны быть установлены до открытия солюшна.

---

## Структура проекта

```
UwU_Driver.sln              — солюшн Visual Studio
UwU_Driver/
  Driver.c                  — DriverEntry, установка/снятие хука, патч реестра
  ldisasm.c / ldisasm.h     — минимальный x64 дизассемблер длин инструкций
  UwU_Driver.inf            — INF-файл драйвера (KMDF, demand-start)
  UwU_Driver.vcxproj        — MSBuild-проект (ConfigurationType=Driver, DriverType=KMDF)
```

---

## Подключаемые библиотеки ядра

| Библиотека | Назначение |
|------------|-----------|
| `ntoskrnl.lib` | Экспорты ядра: `MmGetSystemRoutineAddress`, `ExAllocatePool2`, `IoAllocateMdl`, MDL-функции |
| `wdm.h` / `ntddk.h` | Заголовки WDM/NTDDK — подключаются автоматически тулсетом WDK |
| KMDF runtime | Линкуется неявно через `KmdfLibraryVersion` в INF; отдельный `.lib` не требуется |

---

## Сборка

1. Установить Visual Studio 2022 **и** соответствующий WDK.
2. Открыть `UwU_Driver.sln`.
3. Выбрать конфигурацию **Release | x64** (или Debug | x64).
4. **Build → Build Solution** (`Ctrl+Shift+B`).

Артефакты: `x64\Release\UwU_Driver.sys`, `UwU_Driver.inf`, `uwu_driver.cat`.

---

## Технические детали

### Механизм inline-хука

- Цель: `NtQuerySystemInformation` — найдена через `MmGetSystemRoutineAddress`, без сканирования сигнатур.
- Размер патча: **14 байт** (`FF 25 00000000 <abs64>`) — абсолютный косвенный JMP.
- `ldisasm_aligned()` ищет первую границу инструкции ≥ 14 байт, чтобы копия пролога не обрывалась на середине инструкции.
- `FixRipRelative()` патчит смещения `ModRM mod=00 rm=5` (RIP-relative) в скопированном прологе — абсолютный адрес целевого операнда сохраняется.
- Трамплин выделяется через `ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, ...)`, тег `'uwu1'`.
- Запись в защищённые страницы кода — через MDL (`IoAllocateMdl` → `MmProbeAndLockPages` → `MmMapLockedPagesSpecifyCache` → `MmProtectMdlSystemAddress(PAGE_EXECUTE_READWRITE)`).

### Очищаемые биты

| Бит | Значение |
|-----|---------|
| `0x02` | `CODEINTEGRITY_OPTION_TESTSIGN` |
| `0x08` | UMCI / связанный тестовый флаг |

---

## Требования к запуску

> **Windows 11 должна быть переведена в тестовый режим (Test Mode).**
> Драйвер не имеет EV-сертификата Microsoft, поэтому перед загрузкой необходимо:
> 1. Включить тестовый режим: `bcdedit /set testsigning on` → перезагрузка.
> 2. Подписать `UwU_Driver.sys` **самоподписным сертификатом** (self-signed):
>
> ```powershell
> # Создать самоподписный сертификат (однократно)
> New-SelfSignedCertificate -Subject "CN=UwU Test" -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert
>
> # Экспортировать и добавить в доверенные корневые ЦС и издателей драйверов
> $cert = (Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=UwU Test" })[0]
> Export-Certificate -Cert $cert -FilePath UwU_Test.cer
> Import-Certificate -FilePath UwU_Test.cer -CertStoreLocation Cert:\LocalMachine\Root
> Import-Certificate -FilePath UwU_Test.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
>
> # Подписать драйвер
> signtool sign /sha1 $cert.Thumbprint /fd sha256 /v x64\Release\UwU_Driver.sys
> ```
>
> Без этих шагов Windows откажет в загрузке драйвера с ошибкой `0xC0000428` (недействительная подпись образа).

## Загрузка (тестовая машина / VM)

```powershell
# Включить тестовую подпись (или VM с выключенным Secure Boot)
bcdedit /set testsigning on

# Создать и запустить службу
sc create UwU_Driver type= kernel binPath= "C:\path\to\UwU_Driver.sys"
sc start UwU_Driver

# Просматривать вывод KdPrint через DebugView (фильтр: *UwU*)
```

> Запускать только на выделенной тестовой VM — драйвер патчит код ядра в рантайме.

## Выгрузка

```powershell
sc stop UwU_Driver
sc delete UwU_Driver
```

`DriverUnload` восстанавливает оригинальный пролог `NtQuerySystemInformation` перед освобождением трамплина.
