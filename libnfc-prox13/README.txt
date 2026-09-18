libnfc-prox13 — модификация libnfc 1.8.0 для поддержки считывателя
PROX 13 MHz Reader (ООО "Прокс", www.prox.ru).

Протокол: FD <id> <cmd> <data...> <FCS_lo> <FCS_hi> FE
FCS: CRC-16/CCITT (poly 0x8408, init 0xFFFF, final XOR 0xFFFF).
Байтстаффинг: FD → FF 02, FE → FF 01, FF → FF 00.

Порядок применения:
  1. Скопируйте prox13.c и prox13.h в libnfc/libnfc/drivers/.
  2. Замените libnfc/nfc.c, CMakeLists.txt,
     cmake/modules/LibnfcDrivers.cmake на файлы из этого каталога.
  3. Соберите libnfc:
       mkdir build && cd build
       cmake .. -DLIBNFC_DRIVER_PROX13=ON
       make -j$(nproc)

Конфигурация:
  В libnfc.conf добавьте:
    device.name = "PROX 13 MHz Reader"
    device.connstring = "prox13:/dev/ttyACM0:9600"
  На Windows: "prox13:COM3:9600"
