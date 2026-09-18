mfoc-hardnested-patches — патчи для сборки mfoc-hardnested 0.10.9
под Windows (MinGW-w64) из Linux.

Патчи решают четыре проблемы кросс-компиляции:

  1. configure.ac: AC_CANONICAL_HOST должен вызываться ДО всех проверок
     по $host_os, иначе переменная пуста и case всегда попадает в ветку
     по умолчанию.

  2. configure.ac: проверки -lm и pthread через AC_CHECK_LIB/ACX_PTHREAD
     не работают в кросс-компиляции, потому что требуют запуска
     собранной программы. Заменены на прямое назначение переменных.

  3. src/err.h: в MinGW отсутствует BSD-заголовок err.h. Добавлен shim,
     реализующий err/errx/warn/warnx через fprintf и exit.

  4. Сборка требует явной линковки -lwinpthread через LIBS.

Порядок применения:
  1. Скопируйте configure.ac поверх оригинального.
  2. Скопируйте src/err.h в src/.
  3. autoreconf -vis
  4. ./configure --host=x86_64-w64-mingw32 \
         CC=x86_64-w64-mingw32-gcc \
         PKG_CONFIG=x86_64-w64-mingw32-pkg-config
  5. make -j$(nproc) LIBS="-llzma -lwinpthread"
