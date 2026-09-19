# MIFARE Classic Toolkit
Набор утилит для работы с картами MIFARE Classic и UID-changeable болванками (Zero, OTP, FUID, UFUID, Gen1A/B, Gen2, Gen3, MF3.2). Проект создавался с упором на считыватель PROX 13 MHz Reader (ООО «Прокс»), но также работает с PN532 и другими ридерами, поддерживаемыми libnfc.

Возможности
Чтение полного дампа карты MIFARE Classic 1K/4K в бинарный .mfd или hex-текст.

Запись полного дампа на UID-changeable болванки (Gen1A, Gen1B, Gen2, Gen3, FUID, UFUID, OTP, Zero, MF3.2) и на обычную MIFARE Classic (без смены UID).

Смена UID — отдельная команда с автоматическим выбором метода (APDU → MIFARE direct → MIFARE auth+write).

Запись block 0 целиком — для изменения ATQA, SAK, BCC вместе с UID.

Необратимая блокировка UID — для защиты итоговой болванки от перезаписи.

Определение типа болванки — безопасное (без записи) распознавание Gen1A.

Сброс MIFARE Classic до заводского состояния — все сектора, ключи и access bits возвращаются к заводским значениям.

Управление словарём ключей — загрузка из текстовых файлов, извлечение из бинарных дампов, добавление из командной строки, защита от дубликатов.

mfoc-hardnested — восстановление ключей MIFARE Classic методом Hardnested (собран с патчами для Windows).

Стандартные утилиты libnfc — nfc-mfclassic для чтения/записи карт, nfc-list, nfc-poll и др.

Состав
Готовые утилиты (Windows x86_64)
Каталог bin/:

Файл	Назначение
nfc-dump.exe	Чтение дампа MIFARE Classic 1K/4K
nfc-gen3-writer.exe	Смена UID и запись дампа на magic-карты
nfc-mfclassic.exe	Стандартная утилита libnfc для чтения/записи
nfc-cardtype.exe	Безопасное определение типа болванки (Gen1A)
mf_factory_reset.exe	Сброс карты до заводского состояния
mf_key_dict.exe	Управление словарём ключей
mfoc-hardnested.exe	Атака Hardnested (восстановление ключей)
libnfc.dll	Библиотека libnfc (с драйвером prox13)
libwinpthread-1.dll	Runtime MinGW (для mfoc-hardnested)
Исходники
src/mifare-classic/ — исходники наших утилит (mf_factory_reset.c, mf_key_dict.c) и Makefile для сборки под Linux и Windows.

src/libnfc-utils/ — исходники nfc-dump.c, nfc-gen3-writer.c, nfc-cardtype.c (собираются против установленной libnfc).

Модификации библиотек
libnfc-prox13/ — модифицированные файлы libnfc 1.8.0 для поддержки считывателя PROX 13 MHz Reader (драйвер prox13.c).

mfoc-hardnested-patches/ — патчи для сборки mfoc-hardnested 0.10.9 под Windows (shim err.h, исправления configure.ac).

Быстрый старт (Windows)
Скопируйте содержимое bin/ в одну папку.

Рядом создайте config\libnfc.conf:

text
device.name = "PROX 13 MHz Reader"
device.connstring = "prox13:COM3:9600"
Замените COM3 на ваш порт из Диспетчера устройств.

Откройте cmd.exe в этой папке:

cmd
chcp 65001
nfc-dump.exe
Сборка под Linux
Утилиты из src/mifare-classic/
bash
cd src/mifare-classic
make -f Makefile.linux
libnfc с драйвером prox13
bash
git clone https://github.com/nfc-tools/libnfc.git
cd libnfc
# Применить файлы из libnfc-prox13/ (см. README внутри каталога)
mkdir build && cd build
cmake .. -DLIBNFC_DRIVER_PROX13=ON
make -j$(nproc)
sudo make install
Утилиты nfc-dump, nfc-gen3-writer, nfc-cardtype
bash
cd src/libnfc-utils
make -f Makefile.linux
mfoc-hardnested
bash
git clone https://github.com/nfc-tools/mfoc-hardnested.git
cd mfoc-hardnested
# Применить файлы из mfoc-hardnested-patches/
autoreconf -vis
./configure
make -j$(nproc)
Сборка под Windows (кросс-компиляция из Linux)
Требуется mingw-w64, cmake, pkg-config и кросс-собранные libusb, openssl, liblzma, libnfc. Все библиотеки устанавливаются в /opt/cross-libs.

libnfc (с драйвером prox13)
bash
cd libnfc && mkdir build && cd build
cmake .. \
  -DCMAKE_SYSTEM_NAME=Windows \
  -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
  -DCMAKE_FIND_ROOT_PATH=/opt/cross-libs \
  -DCMAKE_INSTALL_PREFIX=/opt/cross-libs \
  -DLIBNFC_DRIVER_PROX13=ON \
  -DLIBNFC_DRIVER_PN53X_USB=OFF \
  -DLIBNFC_DRIVER_ACR122_USB=OFF
make -j$(nproc)
cp libnfc/libnfc.dll.a /opt/cross-libs/lib/libnfc.a
cp libnfc/libnfc.dll   /opt/cross-libs/lib/
Утилиты nfc-dump, nfc-gen3-writer, nfc-cardtype
bash
cd src/libnfc-utils
make -f Makefile.windows
Или вручную:

bash
x86_64-w64-mingw32-gcc -O2 -Wall -std=c99 \
    -o nfc-dump.exe nfc-dump.c \
    -I /opt/cross-libs/include \
    -L /opt/cross-libs/lib -lnfc -lwinpthread
nfc-mfclassic (из состава libnfc)
bash
cd libnfc
x86_64-w64-mingw32-gcc -O2 -Wall -std=c99 \
    -o nfc-mfclassic.exe \
    utils/nfc-mfclassic.c \
    utils/nfc-utils.c \
    utils/mifare.c \
    -I utils \
    -I include \
    -I /opt/cross-libs/include \
    -L /opt/cross-libs/lib \
    -lnfc -lwinpthread
Перед этим положите utils/err.h — это shim для MinGW (см. mfoc-hardnested-patches/err.h).

Утилиты из src/mifare-classic/
bash
cd src/mifare-classic
make -f Makefile.windows
Использование
Чтение карты — nfc-dump
cmd
:: прочитать и вывести hex на экран (ключи из default.key или встроенные)
nfc-dump.exe

:: сохранить в бинарный .mfd
nfc-dump.exe -o card.mfd

:: использовать свой файл ключей
nfc-dump.exe -k my.keys -o card.mfd

:: позиционные аргументы тоже работают
nfc-dump.exe card.mfd my.keys
Формат файла ключей — 12 hex-цифр на строку, см. раздел «Формат файла ключей».

Запись дампа и смена UID — nfc-gen3-writer
cmd
:: прочитать block 0
nfc-gen3-writer.exe read

:: сменить только UID (метод выбирается автоматически: APDU -> MIFARE)
nfc-gen3-writer.exe setuid 11223344

:: UID из аргумента + запись всего дампа (блоки 1..N)
nfc-gen3-writer.exe setuid 11223344 -d dump.mfd

:: UID из блока 0 дампа + запись всего дампа
nfc-gen3-writer.exe setuid -d dump.mfd

:: только запись дампа, UID не трогается
:: (работает и на обычной MIFARE Classic)
nfc-gen3-writer.exe -d dump.mfd

:: смена UID только через MIFARE (для Gen1A / Gen2 / Zero / OTP)
nfc-gen3-writer.exe setmifare 11223344

:: запись block 0 целиком (меняет UID, ATQA, SAK, BCC)
nfc-gen3-writer.exe setblock 1122334444080400aabbccddeeff0011

:: необратимо заблокировать UID (только Gen3/MF3.2)
nfc-gen3-writer.exe freeze
Стандартное чтение/запись — nfc-mfclassic
cmd
:: прочитать карту, ключи по умолчанию
nfc-mfclassic.exe r a dump.mfd u

:: записать дамп, ключи по умолчанию
nfc-mfclassic.exe w a dump.mfd u
Аргументы:

text
nfc-mfclassic r|w <a|b> <dump.mfd> [f|u]
  r|w   read / write
  a|b   ключ A или B
  f     force — игнорировать предупреждения BCC/SAK
  u     unlock — сначала попробовать стандартные ключи
Определение типа болванки — nfc-cardtype
cmd
nfc-cardtype.exe
Безопасно (без записи) определяет Gen1A и отделяет его от остальных типов. Для Gen2/Gen3/Zero/OTP печатает предупреждение, что точное определение требует записи в block 0.

Сброс карты до заводского состояния — mf_factory_reset
cmd
:: ключи по умолчанию (default.key или FF FF FF FF FF FF)
mf_factory_reset.exe

:: указать файл ключей
mf_factory_reset.exe -k my.keys

:: сбросить также block 0 (только magic-карты)
mf_factory_reset.exe -b
Управление словарём ключей — mf_key_dict
cmd
:: добавить один ключ
mf_key_dict.exe -k A0A1A2A3A4A5

:: добавить ключи из файла
mf_key_dict.exe -s other.keys

:: извлечь ключи из дампа
mf_key_dict.exe -b dump.mfd

:: комбинированная операция
mf_key_dict.exe -d my.keys -s known.keys -b dump.mfd -k FFFFFFFFFFFF
mfoc-hardnested
cmd
:: атака hardnested на карту с известным ключом
mfoc-hardnested.exe -k FFFFFFFFFFFF -O dump.mfd
Формат файла ключей
Текстовый файл, по одному ключу в строке. Формат — 12 hex-цифр (6 байт). Строки, начинающиеся с # или ;, игнорируются.

text
# Пример файла default.key
FFFFFFFFFFFF
A0A1A2A3A4A5
D3F7D3F7D3F7
000000000000
Формат дампа
Поддерживаются три формата, распознаются автоматически:

Бинарный — 1024 байта (1K) или 4096 байт (4K), стандартный .mfd.

Текстовый MCT (MifareClassicTool) — заголовки +Sector: N и hex-строки.

Текстовый nfc-dump — заголовки # sector NN и строки вида NNN: hex....

Все три формата можно скармливать nfc-gen3-writer -d <file> и mfoc-hardnested -O <file>.

Совместимые карты
Тип болванки	Алгоритм смены UID / записи block 0
Gen1A (UID, block 0 открыт)	Прямая запись A0xx без auth
Gen1B	Backdoor 40(7) + 43 + A0xx
Gen2 (CUID)	A0xx после auth дефолтным ключом
Gen3 / MF3.2	APDU 90 FB CC CC 04 <uid>
FUID	Прямая запись (одноразово)
UFUID	Сложная разблокировка + прямая запись
OTP	Прямая запись (одноразово)
Zero / MF / MF2 / MF3	Прямая запись
Обычная MIFARE Classic 1K/4K	UID не меняется; можно писать блоки 1..N
Безопасность
Все операции с MIFARE Classic необратимы. Сброс карты уничтожает все данные в секторах. Запись дампа на magic-карту затирает предыдущее содержимое. Однократные болванки (FUID, OTP) можно записать только один раз. Команда freeze необратима.

Используйте утилиты только на собственных картах. Восстановление чужих ключей и копирование чужих карт может нарушать законодательство.

Зависимости
libnfc (LGPL v3)

libfreefare (LGPL v3)

mfoc-hardnested (GPL v3)

xz-utils (public domain)

Лицензия
Наши утилиты распространяются под LGPL v3. Полные тексты лицензий модифицированных библиотек — в соответствующих каталогах.

Авторы
Проект создан Сорокиным Александром (СПбГУ) с помощью Claude (Anthropic) в ходе итеративной разработки и отладки драйвера PROX 13 MHz Reader и набора утилит для MIFARE Classic.

