/*-
 * nfc-dump — утилита для чтения MIFARE Classic 1K/4K.
 *
 * Использование:
 *   nfc-dump [-k keyfile] [-o dumpfile]
 *   nfc-dump [dumpfile] [keyfile]
 *
 * Если -o не задан — дамп печатается в hex на stdout.
 * Если -k не задан — ищется default.key, затем встроенный список.
 *
 * Формат файла ключей: одна 12-символьная hex-строка (6 байт) на строку.
 * Строки, начинающиеся с '#' или ';', игнорируются.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

#include <nfc/nfc.h>

#define MAX_KEYS 512

static const uint8_t builtin_keys[][6] = {
  { 0xff,0xff,0xff,0xff,0xff,0xff },
  { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
  { 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
  { 0x00,0x00,0x00,0x00,0x00,0x00 },
  { 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
  { 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
  { 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
  { 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
  { 0x71,0x4c,0x5c,0x88,0x6e,0x97 },
  { 0x58,0x7e,0xe5,0xf9,0x35,0x0f },
  { 0xa0,0x47,0x8c,0xc3,0x90,0x91 },
  { 0x53,0x3c,0xb6,0xc7,0x23,0xf6 },
  { 0x8f,0xd0,0xa4,0xf2,0x56,0xe9 },
};

static uint8_t keys[MAX_KEYS][6];
static size_t  keys_count = 0;

static void
keys_add(const uint8_t b[6])
{
  if (keys_count >= MAX_KEYS) return;
  for (size_t i = 0; i < keys_count; i++)
    if (memcmp(keys[i], b, 6) == 0) return;
  memcpy(keys[keys_count++], b, 6);
}

static int
hex_nibble(int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
parse_hex_key(const char *line, uint8_t out[6])
{
  int nib[12], n = 0;
  for (const char *p = line; *p && n < 12; p++) {
    if (*p == '#' || *p == ';') break;
    if (isspace((unsigned char)*p)) continue;
    int v = hex_nibble((unsigned char)*p);
    if (v < 0) return -1;
    nib[n++] = v;
  }
  if (n != 12) return -1;
  for (int i = 0; i < 6; i++)
    out[i] = (uint8_t)((nib[2*i] << 4) | nib[2*i+1]);
  return 0;
}

static int
load_keyfile(const char *path)
{
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  int before = (int)keys_count;
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    uint8_t k[6];
    if (parse_hex_key(line, k) == 0) keys_add(k);
  }
  fclose(f);
  return (int)keys_count - before;
}

static bool
file_exists(const char *path)
{
#ifdef _WIN32
  DWORD a = GetFileAttributesA(path);
  return (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY));
#else
  return access(path, R_OK) == 0;
#endif
}

static void
load_keys(const char *keyfile)
{
  if (keyfile) {
    int n = load_keyfile(keyfile);
    if (n <= 0) {
      fprintf(stderr, "Cannot load keys from '%s'\n", keyfile);
      exit(1);
    }
    fprintf(stderr, "Loaded %d key(s) from %s\n", n, keyfile);
    return;
  }
  if (file_exists("default.key")) {
    int n = load_keyfile("default.key");
    if (n > 0) {
      fprintf(stderr, "Loaded %d key(s) from default.key\n", n);
      return;
    }
  }
  size_t n = sizeof(builtin_keys) / sizeof(builtin_keys[0]);
  for (size_t i = 0; i < n; i++) keys_add(builtin_keys[i]);
  fprintf(stderr, "Using %zu built-in key(s)\n", keys_count);
}

static void
print_key(const uint8_t k[6])
{
  for (int i = 0; i < 6; i++) fprintf(stderr, "%02x", k[i]);
}

static void
print_target(const nfc_target *nt)
{
  if (nt->nm.nmt == NMT_ISO14443A) {
    fprintf(stderr, "  ISO/IEC 14443A (%s)\n",
            str_nfc_baud_rate(nt->nm.nbr));
    fprintf(stderr, "  ATQA: %02x %02x\n",
            nt->nti.nai.abtAtqa[0], nt->nti.nai.abtAtqa[1]);
    fprintf(stderr, "  SAK:  %02x\n", nt->nti.nai.btSak);
    fprintf(stderr, "  UID:  ");
    for (size_t i = 0; i < nt->nti.nai.szUidLen; i++)
      fprintf(stderr, "%02x", nt->nti.nai.abtUid[i]);
    fprintf(stderr, "\n");
  }
}

/* -------------------------------------------------------------------------
 * Прямой вызов MIFARE-команд через nfc_initiator_transceive_bytes().
 *
 * Точная копия поведения nfc_initiator_mifare_cmd() из utils/mifare.c:
 *   - NP_EASY_FRAMING выставляется в true (PN532 сам добавит CRC/parity
 *     и обернёт кадр в InDataExchange / InCommunicateThru как надо);
 *   - прочие свойства не трогаются;
 *   - timeout = -1 (значение по умолчанию libnfc).
 *
 * Кадры:
 *   AUTH      : [0x60|0x61] [block] [key:6] [uid:4]  — 12 байт
 *   READ      : [0x30] [block]                        — 2 байта, ответ 16
 *   WRITE     : [0xA0] [block] [data:16]              — 18 байт
 *   DEC/INC   : [0xC0|0xC1] [block] [value:4]         — 6 байт
 *   TRANSFER  : [0xB0] [block]
 *   RESTORE   : [0xC2] [block]
 *
 * Диагностики (nfc_perror) не печатаем — в отличие от mifare.c.
 * ------------------------------------------------------------------------- */
static bool
my_mifare_cmd(nfc_device *pnd, uint8_t cmd, uint8_t block,
              uint8_t *data, const uint8_t uid[4])
{
  uint8_t abtCmd[2 + 16];
  size_t  szParamLen = 0;
  uint8_t abtRx[265];
  int     res;

  abtCmd[0] = cmd;
  abtCmd[1] = block;

  switch (cmd) {
    case 0x30:                     /* READ */
    case 0xB0:                     /* TRANSFER */
    case 0xC2:                     /* RESTORE */
      szParamLen = 0;
      break;
    case 0x60: case 0x61:          /* AUTH A / AUTH B */
      memcpy(&abtCmd[2], data, 6);
      if (uid) memcpy(&abtCmd[8], uid, 4);
      szParamLen = 10;
      break;
    case 0xA0:                     /* WRITE */
      memcpy(&abtCmd[2], data, 16);
      szParamLen = 16;
      break;
    case 0xC0: case 0xC1:          /* DECREMENT / INCREMENT */
      memcpy(&abtCmd[2], data, 4);
      szParamLen = 4;
      break;
    default:
      return false;
  }

  nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true);

  res = nfc_initiator_transceive_bytes(pnd, abtCmd, 2 + szParamLen,
                                       abtRx, sizeof(abtRx), -1);
  if (res < 0) return false;

  if (cmd == 0x30) {
    if (res != 16 && res != 18) return false;
    memcpy(data, abtRx, 16);
  }
  return true;
}

static bool
try_auth(nfc_device *pnd, const nfc_modulation *nm, const nfc_target *nt,
         uint8_t block, const uint8_t key[6], uint8_t cmd)
{
  if (my_mifare_cmd(pnd, cmd, block, (uint8_t *)key, nt->nti.nai.abtUid))
    return true;
  /* После неудачной auth карта в HALT — перевыбираем */
  nfc_target nt2;
  nfc_initiator_select_passive_target(pnd, *nm, NULL, 0, &nt2);
  return false;
}

static bool
read_sector(nfc_device *pnd, const nfc_modulation *nm, const nfc_target *nt,
            size_t sector, size_t first_block, size_t nblocks,
            uint8_t *out)
{
  uint8_t block0 = (uint8_t)first_block;
  bool    authed = false;
  uint8_t auth_key[6];
  char    auth_type = '?';

  for (size_t i = 0; i < keys_count && !authed; i++) {
    if (try_auth(pnd, nm, nt, block0, keys[i], 0x60)) {
      memcpy(auth_key, keys[i], 6);
      auth_type = 'A';
      authed = true;
    }
  }
  if (!authed) {
    for (size_t i = 0; i < keys_count && !authed; i++) {
      if (try_auth(pnd, nm, nt, block0, keys[i], 0x61)) {
        memcpy(auth_key, keys[i], 6);
        auth_type = 'B';
        authed = true;
      }
    }
  }

  if (!authed) {
    fprintf(stderr, "  sector %02zu: no key found\n", sector);
    memset(out, 0, nblocks * 16);
    return false;
  }

  fprintf(stderr, "  sector %02zu: key %c = ", sector, auth_type);
  print_key(auth_key);
  fprintf(stderr, "\n");

  for (size_t b = 0; b < nblocks; b++) {
    uint8_t blk = (uint8_t)(first_block + b);
    if (!my_mifare_cmd(pnd, 0x30, blk, out + b * 16, NULL)) {
      fprintf(stderr, "    block %03u: read error\n", blk);
      memset(out + b * 16, 0, 16);
    }
  }

  /* MIFARE Classic не гарантирует, что Key A читается с чипа
   * (многие чипы возвращают нули вместо Key A). Утилиты типа
   * mfoc/nfc-mfclassic подставляют найденный ключ, чтобы дамп был
   * пригоден для обратной записи. Делаем так же для Key A. */
  if (auth_type == 'A' && nblocks > 0) {
    memcpy(out + (nblocks - 1) * 16, auth_key, 6);
  }

  return true;
}

static void
print_usage(void)
{
  fprintf(stderr,
    "Usage: nfc-dump [-k keyfile] [-o dumpfile]\n"
    "\n"
    "  -k <file>   файл с ключами\n"
    "              (по умолчанию: default.key, затем встроенный список)\n"
    "  -o <file>   файл дампа\n"
    "              (по умолчанию: hex-вывод на stdout)\n"
    "  -h          эта справка\n"
    "\n"
    "Формат файла ключей: одна 12-символьная hex-строка на строку\n"
    "(6 байт). Строки, начинающиеся с '#' или ';', игнорируются.\n");
}

int
main(int argc, char **argv)
{
  const char *dumpfile = NULL;
  const char *keyfile  = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_usage();
      return 0;
    } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
      keyfile = argv[++i];
    } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
      dumpfile = argv[++i];
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_usage();
      return 1;
    } else {
      if (!dumpfile)      dumpfile = argv[i];
      else if (!keyfile)  keyfile  = argv[i];
      else {
        fprintf(stderr, "Too many positional arguments\n");
        print_usage();
        return 1;
      }
    }
  }

  load_keys(keyfile);

  nfc_context *ctx;
  nfc_init(&ctx);
  if (!ctx) { fprintf(stderr, "nfc_init failed\n"); return 1; }

  nfc_connstring connstrings[8];
  size_t ndev = nfc_list_devices(ctx, connstrings, 8);
  if (ndev == 0) {
    fprintf(stderr, "No NFC device found\n");
    nfc_exit(ctx);
    return 1;
  }

  nfc_device *pnd = nfc_open(ctx, connstrings[0]);
  if (!pnd) {
    fprintf(stderr, "nfc_open failed\n");
    nfc_exit(ctx);
    return 1;
  }

  if (nfc_initiator_init(pnd) < 0) {
    fprintf(stderr, "nfc_initiator_init failed\n");
    nfc_close(pnd);
    nfc_exit(ctx);
    return 1;
  }

  nfc_modulation nm = { .nmt = NMT_ISO14443A, .nbr = NBR_106 };
  nfc_target nt;
  if (nfc_initiator_select_passive_target(pnd, nm, NULL, 0, &nt) <= 0) {
    fprintf(stderr, "No ISO14443-A target found\n");
    nfc_close(pnd);
    nfc_exit(ctx);
    return 1;
  }

  fprintf(stderr, "Found card:\n");
  print_target(&nt);

  if (nt.nti.nai.btSak & 0x20) {
    fprintf(stderr, "Not a MIFARE Classic card (SAK=0x%02x)\n",
            nt.nti.nai.btSak);
    nfc_close(pnd);
    nfc_exit(ctx);
    return 1;
  }

  size_t total_sectors, total_blocks;
  bool is_4k = (nt.nti.nai.abtAtqa[0] == 0x02 && nt.nti.nai.abtAtqa[1] == 0x00);
  if (is_4k) {
    total_sectors = 40;
    total_blocks  = 256;
  } else {
    total_sectors = 16;
    total_blocks  = 64;
  }
  fprintf(stderr, "Card type: MIFARE Classic %s (%zu sectors, %zu blocks)\n",
          is_4k ? "4K" : "1K", total_sectors, total_blocks);

  uint8_t *dump = (uint8_t *)calloc(total_blocks, 16);
  if (!dump) {
    fprintf(stderr, "Out of memory\n");
    nfc_close(pnd);
    nfc_exit(ctx);
    return 1;
  }

  size_t ok_sectors = 0;
  for (size_t s = 0; s < total_sectors; s++) {
    size_t first_block, nblocks;
    if (s < 32) { first_block = s * 4; nblocks = 4; }
    else        { first_block = 128 + (s - 32) * 16; nblocks = 16; }
    if (read_sector(pnd, &nm, &nt, s, first_block, nblocks,
                    dump + first_block * 16))
      ok_sectors++;
  }

  fprintf(stderr, "Read %zu/%zu sectors\n", ok_sectors, total_sectors);

  if (dumpfile) {
    FILE *f = fopen(dumpfile, "wb");
    if (!f) {
      fprintf(stderr, "Cannot write '%s': %s\n", dumpfile, strerror(errno));
    } else {
      fwrite(dump, 1, total_blocks * 16, f);
      fclose(f);
      fprintf(stderr, "Saved %zu bytes to %s\n",
              total_blocks * 16, dumpfile);
    }
  } else {
    for (size_t b = 0; b < total_blocks; b++) {
      size_t s;
      if (b < 128) s = b / 4;
      else         s = 32 + (b - 128) / 16;
      bool is_first_of_sector =
          (b < 128) ? (b % 4 == 0) : ((b - 128) % 16 == 0);
      if (b == 0 || is_first_of_sector)
        fprintf(stdout, "# sector %02zu\n", s);
      fprintf(stdout, "%03zu: ", b);
      for (int k = 0; k < 16; k++)
        fprintf(stdout, "%02x", dump[b * 16 + k]);
      fprintf(stdout, "\n");
    }
  }

  free(dump);
  nfc_close(pnd);
  nfc_exit(ctx);
  return 0;
}