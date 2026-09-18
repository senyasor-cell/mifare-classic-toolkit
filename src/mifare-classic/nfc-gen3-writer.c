/*-
 * nfc-gen3-writer — утилита для смены UID и записи дампа на MIFARE Classic.
 *
 * Использование:
 *   nfc-gen3-writer read
 *   nfc-gen3-writer freeze
 *   nfc-gen3-writer setblock <hex16>
 *   nfc-gen3-writer setmifare <uid>
 *   nfc-gen3-writer setuid <uid>
 *   nfc-gen3-writer setuid <uid> -d <file>
 *   nfc-gen3-writer setuid -d <file>
 *   nfc-gen3-writer -d <file>
 *
 * Режим "-d <file>" (без setuid) пишет только блоки 1..N из дампа,
 * UID карты не трогает. Подходит для обычной MIFARE Classic 1K/4K.
 *
 * Формат дампа:
 *   - текстовый (MifareClassicTool: "+Sector: N" + hex-строки)
 *   - текстовый (nfc-dump: "# sector NN" + "NNN: ...")
 *   - бинарный (1024 / 4096 байт, .mfd)
 *
 * Замечание: на многих Gen3-картах auth возвращает 0 байт вместо
 * 4-байтового Nt. Поэтому «успех auth» = отсутствие ошибки transceive,
 * подтверждается последующим чтением блока.
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

#ifdef _WIN32
#  include <windows.h>
#  define msleep(ms) Sleep(ms)
#else
#  include <unistd.h>
#  define msleep(ms) usleep((ms) * 1000)
#endif

#include <nfc/nfc.h>

static void print_hex(const uint8_t *d, size_t n);
static int  hex_nibble(int c);
static int  parse_hex(const char *hex, uint8_t *out, size_t max_len);

static nfc_modulation g_nm;

/* -------------------------------------------------------------------------
 * APDU для Gen3
 * ------------------------------------------------------------------------- */
static bool
send_apdu(nfc_device *pnd, const uint8_t *apdu, size_t apdu_len,
          uint8_t *resp, size_t *resp_len)
{
  uint8_t abtRx[264];
  int     res;
  uint32_t cycles = 0;

  nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false);
  res = nfc_initiator_transceive_bytes_timed(pnd, apdu, apdu_len,
                                             abtRx, sizeof(abtRx), &cycles);
  nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true);

  if (res < 0) return false;

  if (resp && resp_len) {
    size_t n = (size_t)res;
    if (n > *resp_len) n = *resp_len;
    memcpy(resp, abtRx, n);
    *resp_len = n;
  }
  return true;
}

static bool
apdu_ok(const uint8_t *resp, size_t resp_len)
{
  return (resp_len >= 2 && resp[resp_len - 2] == 0x90 && resp[resp_len - 1] == 0x00);
}

/* -------------------------------------------------------------------------
 * RF-поле и перевыбор
 * ------------------------------------------------------------------------- */
static void
drop_field(nfc_device *pnd, int ms)
{
  nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, false);
  msleep(ms);
  nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, true);
  msleep(50);
}

static bool
uid_matches(nfc_device *pnd, const uint8_t *want, int want_len)
{
  for (int i = 0; i < 5; i++) {
    nfc_target nt;
    if (nfc_initiator_select_passive_target(pnd, g_nm, NULL, 0, &nt) > 0) {
      if ((int)nt.nti.nai.szUidLen == want_len &&
          memcmp(nt.nti.nai.abtUid, want, want_len) == 0) {
        return true;
      }
    }
    msleep(100);
  }
  return false;
}

/* -------------------------------------------------------------------------
 * MIFARE-команды
 * ------------------------------------------------------------------------- */
static bool
raw_mifare(nfc_device *pnd, const uint8_t *tx, size_t tx_len,
           uint8_t *rx, size_t rx_max, int *out_len)
{
  uint8_t abtRx[264];
  int res;

  nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true);
  res = nfc_initiator_transceive_bytes(pnd, tx, tx_len, abtRx, sizeof(abtRx), -1);

  if (out_len) *out_len = (res < 0) ? 0 : res;
  if (res < 0) return false;
  if (rx && rx_max) {
    size_t n = (size_t)res;
    if (n > rx_max) n = rx_max;
    memcpy(rx, abtRx, n);
  }
  return true;
}

static bool
mifare_auth(nfc_device *pnd, uint8_t block, const uint8_t key[6],
            uint8_t cmd, const uint8_t uid[4], int *out_len)
{
  uint8_t tx[12];
  tx[0] = cmd;
  tx[1] = block;
  memcpy(&tx[2], key, 6);
  memcpy(&tx[8], uid, 4);
  return raw_mifare(pnd, tx, 12, NULL, 0, out_len);
}

static bool
mifare_read(nfc_device *pnd, uint8_t block, uint8_t out[16])
{
  uint8_t tx[2] = { 0x30, block };
  int len = 0;
  if (!raw_mifare(pnd, tx, 2, out, 16, &len)) return false;
  return (len >= 16);
}

static bool
mifare_write(nfc_device *pnd, uint8_t block, const uint8_t data[16])
{
  uint8_t tx[18];
  uint8_t rx[4];
  tx[0] = 0xA0;
  tx[1] = block;
  memcpy(&tx[2], data, 16);
  int len = 0;
  if (!raw_mifare(pnd, tx, 18, rx, sizeof(rx), &len)) return false;
  return (len == 0) || (len >= 1 && rx[0] == 0x0A);
}

static bool
try_auth_and_read_block0(nfc_device *pnd, const uint8_t uid4[4],
                         uint8_t block0[16])
{
  static const uint8_t keys[][6] = {
    { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF },
    { 0xA0,0xA1,0xA2,0xA3,0xA4,0xA5 },
    { 0xD3,0xF7,0xD3,0xF7,0xD3,0xF7 },
    { 0x00,0x00,0x00,0x00,0x00,0x00 },
    { 0xB0,0xB1,0xB2,0xB3,0xB4,0xB5 },
    { 0x4D,0x3A,0x99,0xC3,0x51,0xDD },
  };
  size_t nkeys = sizeof(keys) / sizeof(keys[0]);

  for (size_t k = 0; k < nkeys; k++) {
    for (int c = 0; c < 2; c++) {
      uint8_t cmd = c ? 0x61 : 0x60;
      nfc_target nt;
      if (nfc_initiator_select_passive_target(pnd, g_nm, NULL, 0, &nt) <= 0)
        continue;
      int res = -1;
      bool ok = mifare_auth(pnd, 0x00, keys[k], cmd, uid4, &res);
      fprintf(stderr, "  auth try: key ");
      print_hex(keys[k], 6);
      fprintf(stderr, " cmd=%02x -> res=%d %s\n", cmd, res, ok ? "OK" : "fail");
      if (ok) {
        if (mifare_read(pnd, 0x00, block0)) return true;
      }
    }
  }
  return false;
}

/* -------------------------------------------------------------------------
 * Вспомогательные функции
 * ------------------------------------------------------------------------- */
static int
hex_nibble(int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
parse_hex(const char *hex, uint8_t *out, size_t max_len)
{
  size_t n = 0;
  while (*hex && n < max_len) {
    while (*hex && isspace((unsigned char)*hex)) hex++;
    if (!*hex) break;
    int hi = hex_nibble((unsigned char)hex[0]);
    int lo = hex_nibble((unsigned char)hex[1]);
    if (hi < 0 || lo < 0) return -1;
    out[n++] = (uint8_t)((hi << 4) | lo);
    hex += 2;
  }
  return (int)n;
}

static void
print_hex(const uint8_t *d, size_t n)
{
  for (size_t i = 0; i < n; i++) printf("%02x", d[i]);
}

static void
patch_block0_uid(uint8_t block0[16], const uint8_t *uid, int uid_len)
{
  if (uid_len == 4) {
    memcpy(&block0[0], uid, 4);
    block0[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
  } else if (uid_len == 7) {
    memcpy(&block0[0], uid, 3);
    block0[3] = uid[0] ^ uid[1] ^ uid[2];
    memcpy(&block0[4], &uid[3], 4);
    block0[8] = uid[3] ^ uid[4] ^ uid[5] ^ uid[6];
  }
}

/* -------------------------------------------------------------------------
 * Загрузка дампа — текстовый или бинарный.
 * ------------------------------------------------------------------------- */
static uint8_t *
load_dump(const char *path, size_t *out_size)
{
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;

  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz <= 0) { fclose(f); return NULL; }

  uint8_t *raw = (uint8_t *)malloc((size_t)sz + 1);
  if (!raw) { fclose(f); return NULL; }
  size_t rd = fread(raw, 1, (size_t)sz, f);
  fclose(f);
  raw[rd] = 0;

  if ((rd == 1024 || rd == 4096) && memchr(raw, '\n', 64) == NULL) {
    *out_size = rd;
    return raw;
  }

  uint8_t *dump = (uint8_t *)calloc(4096, 1);
  if (!dump) { free(raw); return NULL; }

  size_t dump_pos = 0;
  char  *saveptr = NULL;
  char  *line = strtok_r((char *)raw, "\r\n", &saveptr);

  while (line && dump_pos < 4096) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;

    if (*p == '\0' || *p == '#' || *p == '+' || *p == ';' || *p == '/') {
      line = strtok_r(NULL, "\r\n", &saveptr);
      continue;
    }

    const char *colon = strchr(p, ':');
    if (colon && (colon - p) <= 5) {
      bool ok = true;
      for (const char *q = p; q < colon; q++) {
        if (!isxdigit((unsigned char)*q) &&
            *q != ' ' && *q != '\t') { ok = false; break; }
      }
      if (ok) p = colon + 1;
    }

    uint8_t block[16];
    int     n = 0;
    while (*p && n < 16) {
      while (*p == ' ' || *p == '\t') p++;
      if (!*p) break;
      int hi = hex_nibble((unsigned char)p[0]);
      int lo = hex_nibble((unsigned char)p[1]);
      if (hi < 0 || lo < 0) break;
      block[n++] = (uint8_t)((hi << 4) | lo);
      p += 2;
    }

    if (n == 16) {
      memcpy(dump + dump_pos, block, 16);
      dump_pos += 16;
    }
    line = strtok_r(NULL, "\r\n", &saveptr);
  }

  free(raw);

  if (dump_pos < 1024) { free(dump); return NULL; }
  *out_size = (dump_pos >= 4096) ? 4096 : 1024;
  return dump;
}

/* -------------------------------------------------------------------------
 * Auth сектора: ключ A/B из трейлера дампа, потом дефолтные.
 * ------------------------------------------------------------------------- */
static bool
auth_sector(nfc_device *pnd, uint8_t block, const uint8_t *trailer,
            uint8_t *used_cmd)
{
  static const uint8_t defaults[][6] = {
    { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF },
    { 0xA0,0xA1,0xA2,0xA3,0xA4,0xA5 },
    { 0xD3,0xF7,0xD3,0xF7,0xD3,0xF7 },
    { 0x00,0x00,0x00,0x00,0x00,0x00 },
  };
  uint8_t scratch[16];

#define TRY_AUTH(_key, _cmd) do {                                          \
    nfc_target nt;                                                         \
    if (nfc_initiator_select_passive_target(pnd, g_nm, NULL, 0, &nt) > 0) {\
      uint8_t cur_uid[4];                                                  \
      memcpy(cur_uid, nt.nti.nai.abtUid, 4);                               \
      int rl = 0;                                                          \
      if (mifare_auth(pnd, block, (_key), (_cmd), cur_uid, &rl)) {         \
        if (mifare_read(pnd, block, scratch)) {                            \
          if (used_cmd) *used_cmd = (_cmd);                                \
          return true;                                                     \
        }                                                                  \
      }                                                                    \
    }                                                                      \
  } while (0)

  TRY_AUTH(trailer, 0x60);       /* Key A из дампа */
  TRY_AUTH(trailer + 10, 0x61);  /* Key B из дампа */
  for (size_t k = 0; k < sizeof(defaults) / sizeof(defaults[0]); k++) {
    TRY_AUTH(defaults[k], 0x60);
    TRY_AUTH(defaults[k], 0x61);
  }
#undef TRY_AUTH
  return false;
}

/* -------------------------------------------------------------------------
 * Запись блоков 1..N из дампа (block 0 пропускается).
 * ------------------------------------------------------------------------- */
static int
write_dump_body(nfc_device *pnd, const uint8_t *dump, size_t dump_size)
{
  bool   is_4k = (dump_size == 4096);
  size_t total_sectors = is_4k ? 40 : 16;

  printf("Card size: %s (%zu sectors)\n", is_4k ? "4K" : "1K", total_sectors);

  int written = 0, failed = 0;

  for (size_t s = 0; s < total_sectors; s++) {
    size_t first_block, nblocks;
    if (s < 32) { first_block = s * 4; nblocks = 4; }
    else        { first_block = 128 + (s - 32) * 16; nblocks = 16; }

    const uint8_t *sector_data = dump + first_block * 16;
    const uint8_t *trailer     = sector_data + (nblocks - 1) * 16;

    /* В секторе 0 block 0 не пишем. */
    size_t start_b = (s == 0) ? 1 : 0;

    uint8_t used_cmd = 0;
    if (!auth_sector(pnd, (uint8_t)first_block, trailer, &used_cmd)) {
      fprintf(stderr, "sector %02zu: cannot authenticate\n", s);
      failed += (int)(nblocks - start_b);
      continue;
    }

    printf("sector %02zu: auth %c ok, writing %zu blocks\n",
           s, used_cmd == 0x60 ? 'A' : 'B', nblocks - start_b);

    for (size_t b = start_b; b < nblocks; b++) {
      uint8_t blk = (uint8_t)(first_block + b);
      if (!mifare_write(pnd, blk, sector_data + b * 16)) {
        fprintf(stderr, "  block %03u: write failed\n", blk);
        failed++;
      } else {
        written++;
      }
    }
  }

  printf("Done: wrote %d blocks, failed %d\n", written, failed);
  return failed > 0 ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Команды
 * ------------------------------------------------------------------------- */
static int
cmd_read(nfc_device *pnd)
{
  uint8_t apdu[] = { 0x30, 0x00 };
  uint8_t resp[264];
  size_t  resp_len = sizeof(resp);

  if (send_apdu(pnd, apdu, sizeof(apdu), resp, &resp_len)) {
    printf("Block 0 (APDU): ");
    print_hex(resp, resp_len);
    printf("\n");
    return 0;
  }
  uint8_t b0[16];
  if (mifare_read(pnd, 0x00, b0)) {
    printf("Block 0 (no auth): ");
    print_hex(b0, 16);
    printf("\n");
    return 0;
  }
  printf("Block 0 not readable without auth.\n");
  return 1;
}

static int
cmd_setuid(nfc_device *pnd, const nfc_target *nt, const char *uid_hex)
{
  uint8_t uid[10];
  int uid_len = parse_hex(uid_hex, uid, sizeof(uid));
  if (uid_len != 4 && uid_len != 7) {
    fprintf(stderr, "UID must be 4 or 7 bytes (8 or 14 hex digits)\n");
    return 1;
  }

  if (uid_len == (int)nt->nti.nai.szUidLen &&
      memcmp(uid, nt->nti.nai.abtUid, uid_len) == 0) {
    printf("UID is already ");
    print_hex(uid, uid_len);
    printf(" — nothing to do\n");
    return 0;
  }

  uint8_t uid4[4];
  memcpy(uid4, nt->nti.nai.abtUid, 4);

  /* Способ 1: APDU */
  {
    uint8_t apdu[16];
    apdu[0] = 0x90;
    apdu[1] = 0xFB;
    apdu[2] = 0xCC;
    apdu[3] = 0xCC;
    apdu[4] = (uint8_t)uid_len;
    memcpy(&apdu[5], uid, uid_len);
    uint8_t resp[16];
    size_t  resp_len = sizeof(resp);
    (void)send_apdu(pnd, apdu, 5 + uid_len, resp, &resp_len);
    drop_field(pnd, 200);
    if (uid_matches(pnd, uid, uid_len)) {
      printf("UID changed to: ");
      print_hex(uid, uid_len);
      printf(" (via APDU)\n");
      return 0;
    }
  }
  /* Способ 2: MIFARE direct */
  {
    uint8_t b0[16];
    if (mifare_read(pnd, 0x00, b0)) {
      patch_block0_uid(b0, uid, uid_len);
      (void)mifare_write(pnd, 0x00, b0);
      drop_field(pnd, 200);
      if (uid_matches(pnd, uid, uid_len)) {
        printf("UID changed to: ");
        print_hex(uid, uid_len);
        printf(" (via MIFARE direct)\n");
        return 0;
      }
    }
  }
  /* Способ 3: auth + write */
  {
    uint8_t b0[16];
    if (try_auth_and_read_block0(pnd, uid4, b0)) {
      patch_block0_uid(b0, uid, uid_len);
      (void)mifare_write(pnd, 0x00, b0);
      drop_field(pnd, 200);
      if (uid_matches(pnd, uid, uid_len)) {
        printf("UID changed to: ");
        print_hex(uid, uid_len);
        printf(" (via MIFARE auth+write)\n");
        return 0;
      }
    }
  }
  fprintf(stderr, "All methods failed — UID not changed\n");
  return 1;
}

/* Только запись блоков 1..N из дампа, без изменения UID. */
static int
cmd_write_dump_only(nfc_device *pnd, const char *dump_path)
{
  size_t   dump_size = 0;
  uint8_t *dump = load_dump(dump_path, &dump_size);
  if (!dump) {
    fprintf(stderr, "Cannot load dump '%s' (expected 1024 or 4096 bytes)\n",
            dump_path);
    return 1;
  }
  printf("Dump '%s': %zu bytes, %s\n", dump_path, dump_size,
         dump_size == 4096 ? "4K" : "1K");
  int ret = write_dump_body(pnd, dump, dump_size);
  free(dump);
  return ret;
}

static int
cmd_setmifare(nfc_device *pnd, const nfc_target *nt, const char *uid_hex)
{
  uint8_t uid[10];
  int uid_len = parse_hex(uid_hex, uid, sizeof(uid));
  if (uid_len != 4 && uid_len != 7) {
    fprintf(stderr, "UID must be 4 or 7 bytes (8 or 14 hex digits)\n");
    return 1;
  }

  uint8_t uid4[4];
  memcpy(uid4, nt->nti.nai.abtUid, 4);

  uint8_t b0[16];
  bool direct = mifare_read(pnd, 0x00, b0);
  if (direct) {
    printf("Block 0 (no auth): ");
    print_hex(b0, 16);
    printf("\n");
  } else {
    if (!try_auth_and_read_block0(pnd, uid4, b0)) {
      fprintf(stderr, "Cannot read block 0\n");
      return 1;
    }
    printf("Block 0 (after auth): ");
    print_hex(b0, 16);
    printf("\n");
  }

  patch_block0_uid(b0, uid, uid_len);
  printf("New block 0:          ");
  print_hex(b0, 16);
  printf("\n");

  (void)mifare_write(pnd, 0x00, b0);
  drop_field(pnd, 200);
  if (!uid_matches(pnd, uid, uid_len)) {
    fprintf(stderr, "Write reported done, but UID did not change\n");
    return 1;
  }
  printf("UID changed to: ");
  print_hex(uid, uid_len);
  printf("\n");
  return 0;
}

static int
cmd_setblock(nfc_device *pnd, const char *block_hex)
{
  uint8_t b0[16];
  int block_len = parse_hex(block_hex, b0, sizeof(b0));
  if (block_len != 16) {
    fprintf(stderr, "Block 0 must be 16 bytes (32 hex digits)\n");
    return 1;
  }

  {
    uint8_t apdu[21];
    apdu[0] = 0x90;
    apdu[1] = 0xF0;
    apdu[2] = 0xCC;
    apdu[3] = 0xCC;
    apdu[4] = 0x10;
    memcpy(&apdu[5], b0, 16);
    uint8_t resp[16];
    size_t  resp_len = sizeof(resp);
    (void)send_apdu(pnd, apdu, 21, resp, &resp_len);
    drop_field(pnd, 200);
    if (uid_matches(pnd, b0, 4)) {
      printf("Block 0 written (via APDU)\n");
      return 0;
    }
  }
  (void)mifare_write(pnd, 0x00, b0);
  drop_field(pnd, 200);
  if (uid_matches(pnd, b0, 4)) {
    printf("Block 0 written (via MIFARE direct)\n");
    return 0;
  }
  fprintf(stderr, "Block 0 not written\n");
  return 1;
}

static int
cmd_freeze(nfc_device *pnd)
{
  uint8_t apdu[] = { 0x90, 0xFD, 0x11, 0x11, 0x00 };
  uint8_t resp[16];
  size_t  resp_len = sizeof(resp);

  if (!send_apdu(pnd, apdu, sizeof(apdu), resp, &resp_len)) {
    fprintf(stderr, "Freeze failed (no response)\n");
    return 1;
  }
  if (!apdu_ok(resp, resp_len)) {
    fprintf(stderr, "Freeze failed (SW=");
    print_hex(resp, resp_len);
    fprintf(stderr, ")\n");
    return 1;
  }
  printf("UID frozen permanently\n");
  return 0;
}

static void
usage(const char *prog)
{
  fprintf(stderr,
    "Usage: <command> [args]\n"
    "\n"
    "Commands:\n"
    "  read                            read block 0\n"
    "  freeze                          permanently lock UID (APDU only)\n"
    "  setblock <hex16>                write block 0 (16 bytes hex)\n"
    "  setmifare <uid>                 change UID via MIFARE only\n"
    "  setuid <uid>                    change UID only\n"
    "  setuid <uid> -d <file>          change UID then write dump (1..N)\n"
    "  setuid -d <file>                UID from dump, then write dump\n"
    "  -d <file>                       write dump only, no UID change\n"
    "\n"
    "Dump formats: MCT text (+Sector: N), nfc-dump text (# sector),\n"
    "binary .mfd (1024 or 4096 bytes).\n"
    "\n"
    "Examples:\n"
    "  %s read\n"
    "  %s setuid 11223344\n"
    "  %s setuid 11223344 -d dump.mfd\n"
    "  %s setuid -d dump.mfd\n"
    "  %s -d dump.mfd\n",
    prog, prog, prog, prog, prog);
}

int
main(int argc, char **argv)
{
  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }

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

  g_nm.nmt = NMT_ISO14443A;
  g_nm.nbr = NBR_106;

  nfc_target nt;
  if (nfc_initiator_select_passive_target(pnd, g_nm, NULL, 0, &nt) <= 0) {
    fprintf(stderr, "No ISO14443-A target found\n");
    nfc_close(pnd);
    nfc_exit(ctx);
    return 1;
  }

  printf("Card: ");
  print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
  printf(" (SAK=%02x)\n", nt.nti.nai.btSak);

  int ret = 0;
  const char *cmd = argv[1];

  if (strcmp(cmd, "read") == 0) {
    ret = cmd_read(pnd);

  } else if (strcmp(cmd, "freeze") == 0) {
    ret = cmd_freeze(pnd);

  } else if (strcmp(cmd, "setblock") == 0) {
    if (argc < 3) { usage(argv[0]); ret = 1; }
    else ret = cmd_setblock(pnd, argv[2]);

  } else if (strcmp(cmd, "setmifare") == 0) {
    if (argc < 3) { usage(argv[0]); ret = 1; }
    else ret = cmd_setmifare(pnd, &nt, argv[2]);

  } else if (strcmp(cmd, "setuid") == 0) {
    const char *uid_arg  = NULL;
    const char *dump_arg = NULL;
    for (int i = 2; i < argc; i++) {
      if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
        dump_arg = argv[++i];
      } else if (argv[i][0] != '-') {
        uid_arg = argv[i];
      }
    }

    if (!uid_arg && !dump_arg) {
      fprintf(stderr, "setuid requires <uid> or -d <file>\n");
      usage(argv[0]);
      ret = 1;
    } else if (!uid_arg && dump_arg) {
      /* UID из дампа, затем запись блока 1..N */
      size_t dump_size = 0;
      uint8_t *dump = load_dump(dump_arg, &dump_size);
      if (!dump) {
        fprintf(stderr, "Cannot load dump '%s'\n", dump_arg);
        ret = 1;
      } else {
        uint8_t uid[7];
        int uid_len;
        if (dump[0] == 0x88) { memcpy(uid, &dump[1], 7); uid_len = 7; }
        else                 { memcpy(uid, &dump[0], 4); uid_len = 4; }

        char uid_str[16];
        for (int i = 0; i < uid_len; i++)
          sprintf(uid_str + i * 2, "%02x", uid[i]);
        uid_str[uid_len * 2] = 0;

        printf("Dump '%s': %zu bytes, %s\n", dump_arg, dump_size,
               dump_size == 4096 ? "4K" : "1K");
        printf("UID from dump: %s\n", uid_str);

        ret = cmd_setuid(pnd, &nt, uid_str);
        if (ret == 0) ret = write_dump_body(pnd, dump, dump_size);
        free(dump);
      }
    } else {
      ret = cmd_setuid(pnd, &nt, uid_arg);
      if (ret == 0 && dump_arg) ret = cmd_write_dump_only(pnd, dump_arg);
    }

  } else if (strcmp(cmd, "-d") == 0) {
    if (argc < 3) { usage(argv[0]); ret = 1; }
    else ret = cmd_write_dump_only(pnd, argv[2]);

  } else {
    usage(argv[0]);
    ret = 1;
  }

  nfc_close(pnd);
  nfc_exit(ctx);
  return ret;
}