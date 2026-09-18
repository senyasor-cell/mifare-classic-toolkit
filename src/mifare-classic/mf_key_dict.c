/*
 * mf_key_dict.c — Управление словарём ключей MIFARE Classic.
 *
 * Возможности:
 *   - загрузить существующий словарь (чтобы не создавать дубликаты);
 *   - добавить ключи из текстовых файлов;
 *   - извлечь ключи из бинарных дампов MIFARE Classic (1K / 4K / Mini);
 *   - добавить ключ напрямую из командной строки;
 *   - сохранить результат в файл назначения.
 *
 * Формат файла словаря: текстовый, по одному ключу в строке (12 hex-цифр).
 * Строки, начинающиеся с '#', игнорируются. Пустые строки игнорируются.
 *
 * Сборка (Linux):
 *   gcc -O2 -o mf_key_dict mf_key_dict.c
 *
 * Сборка (Windows, кросс-компиляция):
 *   x86_64-w64-mingw32-gcc -O2 -o mf_key_dict.exe mf_key_dict.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_KEYS        8192
#define DEFAULT_DEST    "default.key"
#define MAX_SRCS        16
#define MAX_DUMPS       16
#define MAX_DIRECT      64

struct key_entry { uint8_t key[6]; };

static struct key_entry keys[MAX_KEYS];
static int num_keys = 0;

/* -------- Работа с множеством ключей -------- */
static int key_exists(const uint8_t k[6]) {
    for (int i = 0; i < num_keys; i++)
        if (memcmp(keys[i].key, k, 6) == 0) return 1;
    return 0;
}

/* Возвращает 1 если ключ добавлен, 0 если уже есть, -1 при переполнении */
static int add_key(const uint8_t k[6]) {
    if (key_exists(k)) return 0;
    if (num_keys >= MAX_KEYS) return -1;
    memcpy(keys[num_keys].key, k, 6);
    num_keys++;
    return 1;
}

/* Парсит 12 hex-цифр (разделители допустимы). */
static int parse_key(const char *str, uint8_t out[6]) {
    unsigned int b[6];
    if (sscanf(str, "%2x%2x%2x%2x%2x%2x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
    return 0;
}

static void print_key(const uint8_t k[6]) {
    for (int i = 0; i < 6; i++) printf("%02X", k[i]);
}

/* -------- Загрузка текстового файла-источника -------- */
static int load_keys_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Не удалось открыть файл-источник: %s\n", filename);
        return -1;
    }
    char line[256];
    int added = 0, dup = 0, bad = 0;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        char *cr = strchr(line, '\r'); if (cr) *cr = 0;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0 || *p == '#') continue;

        uint8_t k[6];
        if (parse_key(p, k) < 0) {
            fprintf(stderr, "  Пропускаю некорректную строку: %s\n", p);
            bad++;
            continue;
        }
        int r = add_key(k);
        if (r > 0) added++;
        else if (r == 0) dup++;
        else { fprintf(stderr, "  Переполнение словаря\n"); break; }
    }
    fclose(f);
    printf("%-40s  +%-4d  дубликатов: %-3d  некорректных: %d\n",
           filename, added, dup, bad);
    return 0;
}

/* -------- Извлечение ключей из бинарного дампа -------- */
static int load_binary_dump(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Не удалось открыть дамп: %s\n", filename);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fprintf(stderr, "Пустой файл: %s\n", filename);
        fclose(f);
        return -1;
    }
    uint8_t *data = (uint8_t *)malloc((size_t)sz);
    if (!data) {
        fprintf(stderr, "malloc failed\n");
        fclose(f);
        return -1;
    }
    if (fread(data, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "Ошибка чтения файла: %s\n", filename);
        fclose(f);
        free(data);
        return -1;
    }
    fclose(f);

    /* Определяем layout по размеру */
    int sectors = 0;
    if      ((size_t)sz == 16 * 64)          sectors = 16;   /* 1K  */
    else if ((size_t)sz == 32 * 64 + 8 * 256) sectors = 40;  /* 4K  */
    else if ((size_t)sz == 5 * 64)           sectors = 5;    /* Mini */
    else {
        fprintf(stderr,
            "  %s: неизвестный размер %ld байт "
            "(ожидалось 1024, 4096 или 320)\n",
            filename, sz);
        free(data);
        return -1;
    }

    int added = 0, dup = 0;
    size_t offset = 0;
    for (int sec = 0; sec < sectors; sec++) {
        size_t sec_size = (sec < 32) ? 4 * 16 : 16 * 16;
        size_t trailer_off = offset + sec_size - 16;
        /* Key A: байты 0..5, Key B: байты 10..15 */
        uint8_t ka[6], kb[6];
        memcpy(ka, data + trailer_off,     6);
        memcpy(kb, data + trailer_off + 10, 6);

        int r = add_key(ka);
        if (r > 0) added++; else if (r == 0) dup++;
        r = add_key(kb);
        if (r > 0) added++; else if (r == 0) dup++;

        offset += sec_size;
    }
    free(data);
    printf("%-40s  +%-4d  дубликатов: %-3d  секторов: %d\n",
           filename, added, dup, sectors);
    return 0;
}

/* -------- Сохранение -------- */
static int save_keys(const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Не удалось записать файл: %s\n", filename);
        return -1;
    }
    fprintf(f, "# Файл ключей MIFARE Classic\n");
    fprintf(f, "# Формат: 12 hex-цифр (6 байт) на строку.\n");
    fprintf(f, "# Строки, начинающиеся с #, игнорируются.\n");
    fprintf(f, "# Сгенерировано mf_key_dict.\n\n");

    for (int i = 0; i < num_keys; i++) {
        for (int j = 0; j < 6; j++) fprintf(f, "%02X", keys[i].key[j]);
        fprintf(f, "\n");
    }
    fclose(f);
    printf("\nСохранено ключей: %d -> %s\n", num_keys, filename);
    return 0;
}

/* -------- Справка -------- */
static void usage(const char *prog) {
    printf("Использование: %s [опции]\n", prog);
    printf("\nОпции (можно повторять):\n");
    printf("  -d <file>   файл назначения (по умолчанию %s)\n", DEFAULT_DEST);
    printf("  -s <file>   файл-источник ключей (текстовый словарь)\n");
    printf("  -b <file>   бинарный дамп MIFARE Classic (MFD) — извлечь ключи\n");
    printf("  -k <hex>    добавить ключ напрямую (12 hex-цифр)\n");
    printf("  -h          эта справка\n");
    printf("\nПримеры:\n");
    printf("  %s -k A0A1A2A3A4A5\n", prog);
    printf("  %s -d my.keys -s other.keys -b dump.mfd -k FFFFFFFFFFFF\n", prog);
    printf("  %s -b dump1.mfd -b dump2.mfd\n", prog);
}

int main(int argc, char *argv[]) {
    const char *destfile = DEFAULT_DEST;
    const char *srcfiles[MAX_SRCS];  int n_srcfiles  = 0;
    const char *dumpfiles[MAX_DUMPS]; int n_dumpfiles = 0;
    const char *directkeys[MAX_DIRECT]; int n_directkeys = 0;

    /* ---- Разбор аргументов ---- */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            destfile = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            if (n_srcfiles  >= MAX_SRCS)  { fprintf(stderr, "Слишком много -s\n");  return 1; }
            srcfiles[n_srcfiles++] = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            if (n_dumpfiles >= MAX_DUMPS) { fprintf(stderr, "Слишком много -b\n");  return 1; }
            dumpfiles[n_dumpfiles++] = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            if (n_directkeys >= MAX_DIRECT) { fprintf(stderr, "Слишком много -k\n"); return 1; }
            directkeys[n_directkeys++] = argv[++i];
        } else {
            fprintf(stderr, "Неизвестный аргумент: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (n_srcfiles == 0 && n_dumpfiles == 0 && n_directkeys == 0) {
        fprintf(stderr, "Нечего добавлять. Укажите -s, -b или -k.\n\n");
        usage(argv[0]);
        return 1;
    }

    printf("=== Обновление словаря ключей ===\n");
    printf("Файл назначения: %s\n\n", destfile);

    /* ---- 1. Загружаем существующий словарь ---- */
    {
        FILE *f = fopen(destfile, "r");
        if (f) {
            char line[256];
            int existing = 0;
            while (fgets(line, sizeof(line), f)) {
                char *nl = strchr(line, '\n'); if (nl) *nl = 0;
                char *cr = strchr(line, '\r'); if (cr) *cr = 0;
                char *p = line;
                while (*p == ' ' || *p == '\t') p++;
                if (*p == 0 || *p == '#') continue;
                uint8_t k[6];
                if (parse_key(p, k) < 0) continue;
                if (add_key(k) > 0) existing++;
            }
            fclose(f);
            printf("Загружено из %s: %d ключей\n\n", destfile, existing);
        } else {
            printf("%s не существует — будет создан\n\n", destfile);
        }
    }

    /* ---- 2. Источники (текстовые словари) ---- */
    if (n_srcfiles > 0) {
        printf("Загрузка текстовых словарей:\n");
        for (int i = 0; i < n_srcfiles; i++) load_keys_file(srcfiles[i]);
        printf("\n");
    }

    /* ---- 3. Бинарные дампы ---- */
    if (n_dumpfiles > 0) {
        printf("Извлечение ключей из дампов:\n");
        for (int i = 0; i < n_dumpfiles; i++) load_binary_dump(dumpfiles[i]);
        printf("\n");
    }

    /* ---- 4. Прямые ключи ---- */
    if (n_directkeys > 0) {
        printf("Прямое добавление ключей:\n");
        for (int i = 0; i < n_directkeys; i++) {
            uint8_t k[6];
            if (parse_key(directkeys[i], k) < 0) {
                fprintf(stderr, "  %s: некорректный ключ, пропущен\n", directkeys[i]);
                continue;
            }
            int r = add_key(k);
            printf("  ");
            print_key(k);
            printf("  -> %s\n", r > 0 ? "добавлен" : "уже есть");
        }
        printf("\n");
    }

    /* ---- 5. Сохранение ---- */
    if (save_keys(destfile) < 0) return 1;

    return 0;
}
