/*
 * mf_factory_reset.c — Сброс MIFARE Classic до заводского состояния.
 *
 * Заводское состояние сектора:
 *   - data-блоки: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 *   - трейлер:    FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF
 *
 * Безопасность:
 *   - Работает ТОЛЬКО с классическими картами (строгая проверка SAK).
 *   - После записи КАЖДЫЙ блок читается обратно и сравнивается.
 *   - При несовпадении сектор считается не сброшенным.
 *
 * Файл ключей (по умолчанию default.key) — текстовый, по одному ключу
 * в строке (12 hex-цифр). Строки с # — комментарии.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <nfc/nfc.h>

#define MAX_KEYS            256
#define BLOCK_SIZE          16
#define DEFAULT_KEYFILE     "default.key"

static const uint8_t FACTORY_TRAILER[16] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x07, 0x80, 0x69,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

struct key_entry { uint8_t key[6]; };
static struct key_entry keys[MAX_KEYS];
static int num_keys = 0;

static void die(const char *msg) {
    fprintf(stderr, "Ошибка: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* -------- Классификация карт -------- */
/* Возвращает количество секторов или 0, если это не MIFARE Classic. */
static int classic_sectors_by_sak(uint8_t sak) {
    switch (sak) {
        case 0x08: case 0x88:  return 16;   /* 1K */
        case 0x18: case 0x98:  return 40;   /* 4K */
        case 0x09:             return 5;    /* Mini */
        default:               return 0;    /* не Classic */
    }
}

/* -------- Загрузка ключей -------- */
static void load_keys(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Не найден файл ключей: %s\n", filename);
        fprintf(stderr, "Использую FF FF FF FF FF FF\n\n");
        memset(keys[0].key, 0xFF, 6);
        num_keys = 1;
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        char *cr = strchr(line, '\r'); if (cr) *cr = 0;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0 || *p == '#') continue;
        if (strlen(p) < 12) continue;

        unsigned int b[6];
        if (sscanf(p, "%2x%2x%2x%2x%2x%2x",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
            fprintf(stderr, "Пропускаю некорректную строку: %s\n", p);
            continue;
        }
        for (int i = 0; i < 6; i++) keys[num_keys].key[i] = (uint8_t)b[i];
        num_keys++;
        if (num_keys >= MAX_KEYS) break;
    }
    fclose(f);

    if (num_keys == 0) {
        fprintf(stderr, "Файл ключей пуст, использую FF FF FF FF FF FF\n");
        memset(keys[0].key, 0xFF, 6);
        num_keys = 1;
    }

    printf("Загружено ключей: %d\n", num_keys);
    for (int i = 0; i < num_keys; i++) {
        printf("  [%2d] ", i);
        for (int j = 0; j < 6; j++) printf("%02X ", keys[i].key[j]);
        printf("\n");
    }
    printf("\n");
}

/* -------- Геометрия -------- */
static int sector_first_block(int sector) {
    if (sector < 32) return sector * 4;
    return 128 + (sector - 32) * 16;
}
static int sector_block_count(int sector) {
    return sector < 32 ? 4 : 16;
}

/* -------- Транзакции -------- */
static int read_block(nfc_device *pnd, uint8_t block, uint8_t data[16]) {
    uint8_t cmd[2] = { 0x30, block };
    uint8_t resp[16];
    int res = nfc_initiator_transceive_bytes(pnd, cmd, 2, resp, 16, 0);
    if (res < 16) return -1;
    memcpy(data, resp, 16);
    return 0;
}

static int write_block(nfc_device *pnd, uint8_t block, const uint8_t data[16]) {
    uint8_t cmd[18];
    uint8_t resp[8];
    cmd[0] = 0xA0;
    cmd[1] = block;
    memcpy(&cmd[2], data, 16);
    int res = nfc_initiator_transceive_bytes(pnd, cmd, 18, resp, sizeof(resp), 0);
    /* Некоторые ридеры возвращают 1 байт статуса, некоторые 0.
     * Если вернулось >= 2 байт и первый из них явно похож на NAK — это ошибка.
     * Точную проверку делаем через read-back. */
    if (res < 0) return -1;
    return 0;
}

/* Запись с обязательным чтением обратно */
static int write_and_verify(nfc_device *pnd, uint8_t block, const uint8_t data[16]) {
    if (write_block(pnd, block, data) < 0) return -1;
    uint8_t readback[16];
    if (read_block(pnd, block, readback) < 0) return -1;
    if (memcmp(readback, data, 16) != 0) return -1;
    return 0;
}

/* Аутентификация. Проверяем ответ по длине/содержимому. */
static int authenticate(nfc_device *pnd, uint8_t block, uint8_t type,
                        const uint8_t key[6]) {
    uint8_t cmd[8];
    uint8_t resp[8];
    cmd[0] = type;
    cmd[1] = block;
    memcpy(&cmd[2], key, 6);

    int res = nfc_initiator_transceive_bytes(pnd, cmd, 8, resp, sizeof(resp), 0);
    if (res < 0) return -1;

    /* На PN532 успешная аутентификация возвращает 0 байт.
     * На некоторых ридерах (PROX) — 1 байт статуса ACK (0x55 или 0x0A).
     * Если вернулось 1 байт и он НЕ похож на ACK — считаем ошибкой. */
    if (res == 1) {
        if (resp[0] != 0x55 && resp[0] != 0x0A && resp[0] != 0x00)
            return -1;
    }
    /* Если вернулось больше 2 байт "данных" на команду аутентификации —
     * это подозрительно, скорее всего карта не Classic. */
    if (res > 4) return -1;

    return 0;
}

static int try_auth_any(nfc_device *pnd, uint8_t block) {
    for (int i = 0; i < num_keys; i++)
        if (authenticate(pnd, block, 0x60, keys[i].key) >= 0) return 0;
    for (int i = 0; i < num_keys; i++)
        if (authenticate(pnd, block, 0x61, keys[i].key) >= 0) return 0;
    return -1;
}

/* Дополнительная проверка: читаем блок 0 и убеждаемся, что карта
 * ведёт себя как MIFARE Classic (производитель = UID[0]). */
static int sanity_check_classic(nfc_device *pnd, const uint8_t *uid, size_t uid_len) {
    if (uid_len < 4) return -1;
    uint8_t block0[16];
    if (read_block(pnd, 0, block0) < 0) return -1;
    /* В блоке 0 первые 4 байта — UID (для 4-байтового UID).
     * Проверим, что они совпадают с UID, который вернул ридер. */
    if (memcmp(block0, uid, 4) != 0) return -1;
    return 0;
}

/* -------- Reset блока 0 (только для magic-карт) -------- */
static int reset_block0(nfc_device *pnd, const uint8_t uid[4]) {
    uint8_t block0[16];
    uint8_t bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
    block0[0] = uid[0]; block0[1] = uid[1];
    block0[2] = uid[2]; block0[3] = uid[3];
    block0[4] = bcc;
    block0[5] = 0x08;
    block0[6] = 0x04; block0[7] = 0x00;
    memset(&block0[8], 0, 8);

    uint8_t resp[8];

    /* Gen2 */
    {
        uint8_t cmd[18] = { 0xA0, 0x00 };
        memcpy(&cmd[2], block0, 16);
        if (nfc_initiator_transceive_bytes(pnd, cmd, 18, resp, sizeof(resp), 0) >= 0) {
            uint8_t rb[16];
            if (read_block(pnd, 0, rb) >= 0 && memcmp(rb, block0, 16) == 0)
                return 0;
        }
    }
    /* Gen1A */
    {
        uint8_t c40[1] = { 0x40 };
        if (nfc_initiator_transceive_bits(pnd, c40, 7, NULL, resp, sizeof(resp), NULL) >= 0) {
            uint8_t c43[1] = { 0x43 };
            if (nfc_initiator_transceive_bytes(pnd, c43, 1, resp, sizeof(resp), 0) >= 0) {
                uint8_t c2[2] = { 0xA0, 0x00 };
                if (nfc_initiator_transceive_bytes(pnd, c2, 2, resp, sizeof(resp), 0) >= 0) {
                    if (nfc_initiator_transceive_bytes(pnd, block0, 16, resp, sizeof(resp), 0) >= 0) {
                        uint8_t rb[16];
                        if (read_block(pnd, 0, rb) >= 0 && memcmp(rb, block0, 16) == 0)
                            return 0;
                    }
                }
            }
        }
    }
    /* Gen3 */
    {
        uint8_t apdu[21] = { 0x90, 0xF0, 0xCC, 0xCC, 0x10 };
        memcpy(&apdu[5], block0, 16);
        if (nfc_initiator_transceive_bytes(pnd, apdu, 21, resp, sizeof(resp), 0) >= 0) {
            uint8_t rb[16];
            if (read_block(pnd, 0, rb) >= 0 && memcmp(rb, block0, 16) == 0)
                return 0;
        }
    }
    return -1;
}

/* -------- main -------- */
int main(int argc, char *argv[]) {
    const char *keyfile = DEFAULT_KEYFILE;
    int do_block0 = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Использование: %s [-k keyfile] [-b]\n", argv[0]);
            printf("  -k keyfile   файл ключей (по умолчанию %s)\n", DEFAULT_KEYFILE);
            printf("  -b           также сбросить блок 0 (только для magic-карт)\n");
            return 0;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            keyfile = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0) {
            do_block0 = 1;
        } else {
            fprintf(stderr, "Неизвестный аргумент: %s\n", argv[i]);
            return 1;
        }
    }

    printf("=== Сброс MIFARE Classic до заводского состояния ===\n");
    printf("Файл ключей: %s\n\n", keyfile);

    load_keys(keyfile);

    nfc_context *context;
    nfc_init(&context);
    if (!context) die("Не удалось инициализировать libnfc");

    nfc_connstring connstrings[1];
    if (nfc_list_devices(context, connstrings, 1) == 0) {
        nfc_exit(context);
        die("NFC-устройство не найдено");
    }
    nfc_device *pnd = nfc_open(context, connstrings[0]);
    if (!pnd) {
        nfc_exit(context);
        die("Не удалось открыть NFC-устройство");
    }
    if (nfc_initiator_init(pnd) < 0) {
        nfc_close(pnd);
        nfc_exit(context);
        die("nfc_initiator_init failed");
    }

    nfc_modulation nm = { NMT_ISO14443A, NBR_106 };
    nfc_target nt;
    if (nfc_initiator_select_passive_target(pnd, nm, NULL, 0, &nt) <= 0) {
        nfc_close(pnd);
        nfc_exit(context);
        die("Карта не обнаружена");
    }

    printf("Карта обнаружена:\n");
    printf("  UID: ");
    for (size_t i = 0; i < nt.nti.nai.szUidLen; i++)
        printf("%02X ", nt.nti.nai.abtUid[i]);
    printf("\n");
    printf("  SAK: 0x%02X\n", nt.nti.nai.btSak);

    /* === Строгая проверка: это должна быть MIFARE Classic === */
    int sectors = classic_sectors_by_sak(nt.nti.nai.btSak);
    if (sectors == 0) {
        fprintf(stderr,
            "\n[!] SAK 0x%02X не соответствует MIFARE Classic.\n"
            "    Вероятно, это DESFire, SmartMX или другая карта.\n"
            "    Сброс отменён.\n", nt.nti.nai.btSak);
        nfc_close(pnd);
        nfc_exit(context);
        return 2;
    }

    int total_blocks = (sectors <= 16) ? sectors * 4 : 128 + (sectors - 32) * 16;
    printf("  Секторов: %d, всего блоков: %d\n", sectors, total_blocks);

    /* === Проверка: блок 0 действительно читается и UID совпадает === */
    if (sanity_check_classic(pnd, nt.nti.nai.abtUid, nt.nti.nai.szUidLen) < 0) {
        fprintf(stderr,
            "\n[!] Карта не отвечает на чтение блока 0 как MIFARE Classic.\n"
            "    Сброс отменён.\n");
        nfc_close(pnd);
        nfc_exit(context);
        return 2;
    }
    printf("  Проверка: блок 0 читается, UID совпадает — OK\n\n");

    if (do_block0) {
        printf("[0/1] Сброс блока 0 (magic)...\n");
        uint8_t uid4[4];
        memcpy(uid4, nt.nti.nai.abtUid, 4);
        if (reset_block0(pnd, uid4) == 0)
            printf("  Блок 0 записан и проверен\n\n");
        else
            printf("  Не удалось записать блок 0 (обычная карта?)\n\n");
    }

    printf("[1/1] Сброс секторов (с проверкой чтением)...\n\n");

    uint8_t zero_block[16] = { 0 };
    int ok_count = 0, fail_count = 0;

    for (int sec = 0; sec < sectors; sec++) {
        int first_block = sector_first_block(sec);
        int n_blocks = sector_block_count(sec);
        int trailer_block = first_block + n_blocks - 1;

        printf("Сектор %2d (блоки %3d..%3d): ", sec, first_block, trailer_block);

        if (try_auth_any(pnd, first_block) < 0) {
            printf("ошибка аутентификации\n");
            fail_count++;
            continue;
        }

        int ok = 1;
        for (int b = first_block; b < trailer_block; b++) {
            if (write_and_verify(pnd, b, zero_block) < 0) { ok = 0; break; }
        }
        if (!ok) { printf("ошибка записи data-блоков\n"); fail_count++; continue; }

        if (write_and_verify(pnd, trailer_block, FACTORY_TRAILER) < 0) {
            printf("ошибка записи трейлера\n");
            fail_count++;
            continue;
        }

        printf("OK\n");
        ok_count++;
    }

    printf("\n=== Готово ===\n");
    printf("Успешно сброшено секторов: %d из %d\n", ok_count, sectors);
    if (fail_count > 0)
        printf("Не удалось: %d\n", fail_count);

    nfc_close(pnd);
    nfc_exit(context);
    return fail_count > 0 ? 1 : 0;
}