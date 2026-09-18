/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Driver for "13 MHz Reader" (PROX, ООО "Прокс")
 * Protocol: FD <id> <cmd> <data...> <fcs_lo> <fcs_hi> FE
 * FCS: CRC-16/CCITT (poly 0x8408, init 0xFFFF, final XOR 0xFFFF)
 * Byte stuffing: 0xFD → FF 02, 0xFE → FF 01, 0xFF → FF 00
 * ACK: cmd=0x2A, payload = 1 байт статуса (0x55 = OK)
 *
 * Драйвер поддерживает два режима:
 *   - ISO14443-4 (DESFire): APDU через универсальную команду 0x4A с PCB.
 *   - MIFARE Classic: команды 0x60/0x61/0x30/0xA0/... транслируются
 *     в нативные команды PROX 0x50/0x51/0x52/0x53/0x54/0x55/0x56/0x57.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include "prox13.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#ifdef _WIN32
#  include <windows.h>
static void prox13_sleep_ms(int ms) { Sleep(ms); }
#else
#  include <time.h>
static void prox13_sleep_ms(int ms) {
  struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
  nanosleep(&ts, NULL);
}
#endif

#include <nfc/nfc.h>

#include "drivers.h"
#include "nfc-internal.h"
#include "uart.h"

#define PROX13_DRIVER_NAME   "prox13"
#define PROX13_DEFAULT_SPEED 9600

#define LOG_CATEGORY "libnfc.driver.prox13"
#define LOG_GROUP    NFC_LOG_GROUP_DRIVER

/* Service bytes */
#define P13_START   0xFD
#define P13_STOP    0xFE
#define P13_ESC     0xFF
#define P13_ESC_FD  0x02
#define P13_ESC_FE  0x01
#define P13_ESC_FF  0x00

#define P13_ACK_CODE   0x2A
#define P13_STATUS_OK  0x55
#define P13_NOT_READY  0xF1

#define P13_MAX_RAW  512
#define P13_MAX_WIRE 1100

/* General commands */
#define P13_CMD_DEVICE_HEADER 0x00
#define P13_CMD_WRITE_PARAMS  0x01
#define P13_CMD_READ_PARAMS   0x02
#define P13_CMD_POWER_CTRL    0x03
#define P13_CMD_LED_CTRL      0x21
#define P13_CMD_PUMP_RESET    0x22
#define P13_CMD_PUMP_OFF      0x23

/* ISO14443A */
#define P13_CMD_REQUEST       0x40
#define P13_CMD_HALT          0x43
#define P13_CMD_ANTICOLL_SEL  0x44
#define P13_CMD_REQ_ANTICOLL  0x45
#define P13_CMD_REQ_RESELECT  0x46
#define P13_CMD_TRANSCEIVE_A  0x4A
#define P13_CMD_SET_RF_SPEED  0x4F

/* MIFARE Classic native commands */
#define P13_CMD_MIFARE_AUTH     0x50
#define P13_CMD_MIFARE_READ16   0x51
#define P13_CMD_MIFARE_WRITE16  0x52
#define P13_CMD_MIFARE_WRITE4   0x53
#define P13_CMD_MIFARE_INCR     0x54
#define P13_CMD_MIFARE_DECR     0x55
#define P13_CMD_MIFARE_TRANSFER 0x56
#define P13_CMD_MIFARE_RESTORE  0x57

struct prox13_data {
  serial_port port;
  uint8_t     frame_id;
  bool        has_cached_target;
  nfc_target  cached_target;
  uint8_t     pcb_ns;
};

#define DRIVER_DATA(pnd) ((struct prox13_data *)(pnd->driver_data))

/* ---------- FCS (CRC-16/CCITT, reflected) ---------- */
static uint16_t
prox13_fcs(const uint8_t *data, size_t len)
{
  uint16_t fcs = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    fcs ^= data[i];
    for (int j = 0; j < 8; j++) {
      if (fcs & 1)
        fcs = (fcs >> 1) ^ 0x8408;
      else
        fcs >>= 1;
    }
  }
  return fcs ^ 0xFFFF;
}

/* ---------- Byte stuffing ---------- */
static bool
prox13_stuff_byte(uint8_t b, uint8_t *out, size_t *pos, size_t max)
{
  if (*pos + 2 > max) return false;
  switch (b) {
    case P13_START: out[(*pos)++] = P13_ESC; out[(*pos)++] = P13_ESC_FD; return true;
    case P13_STOP:  out[(*pos)++] = P13_ESC; out[(*pos)++] = P13_ESC_FE; return true;
    case P13_ESC:   out[(*pos)++] = P13_ESC; out[(*pos)++] = P13_ESC_FF; return true;
    default:        out[(*pos)++] = b; return true;
  }
}

/* ---------- Build raw frame ---------- */
static size_t
prox13_build_raw(uint8_t *out, size_t out_max,
                 uint8_t id, uint8_t cmd,
                 const uint8_t *data, size_t data_len)
{
  size_t pos = 0;
  if (pos + 2 + data_len + 2 > out_max) return 0;
  out[pos++] = id;
  out[pos++] = cmd;
  if (data_len) {
    memcpy(&out[pos], data, data_len);
    pos += data_len;
  }
  uint16_t fcs = prox13_fcs(out, pos);
  out[pos++] = fcs & 0xFF;
  out[pos++] = (fcs >> 8) & 0xFF;
  return pos;
}

/* ---------- Send frame ---------- */
static int
prox13_send_frame(nfc_device *pnd, uint8_t id, uint8_t cmd,
                  const uint8_t *tx_data, size_t tx_len, int timeout)
{
  struct prox13_data *d = DRIVER_DATA(pnd);

  uint8_t raw[P13_MAX_RAW];
  size_t raw_len = prox13_build_raw(raw, sizeof(raw), id, cmd, tx_data, tx_len);
  if (raw_len == 0) return -1;

  uint8_t wire[P13_MAX_WIRE];
  size_t wpos = 0;
  wire[wpos++] = P13_START;
  for (size_t i = 0; i < raw_len; i++) {
    if (!prox13_stuff_byte(raw[i], wire, &wpos, sizeof(wire))) return -1;
  }
  if (wpos + 1 > sizeof(wire)) return -1;
  wire[wpos++] = P13_STOP;

  if (uart_send(d->port, wire, wpos, timeout) != 0) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "TX failed (cmd 0x%02X)", cmd);
    return -1;
  }
  return 0;
}

/* ---------- Receive one frame ---------- */
static int
prox13_recv_frame(nfc_device *pnd,
                  uint8_t *out_id, uint8_t *out_cmd,
                  uint8_t *out_payload, size_t *out_len,
                  size_t out_max, int timeout_ms)
{
  struct prox13_data *d = DRIVER_DATA(pnd);

  uint8_t  resp_raw[P13_MAX_RAW];
  size_t   resp_pos = 0;
  int      state = 0;
  int      elapsed = 0;
  bool     done = false;

  while (elapsed < timeout_ms && !done) {
    uint8_t b;
    if (uart_receive(d->port, &b, 1, NULL, 50) != 0) {
      elapsed += 50;
      continue;
    }
    switch (state) {
      case 0:
        if (b == P13_START) state = 1;
        break;
      case 1:
        if (b == P13_STOP) {
          done = true;
        } else if (b == P13_ESC) {
          state = 2;
        } else if (b == P13_START) {
          resp_pos = 0;
        } else {
          if (resp_pos >= sizeof(resp_raw)) return -1;
          resp_raw[resp_pos++] = b;
        }
        break;
      case 2:
        if (b == P13_ESC_FF)      resp_raw[resp_pos++] = P13_ESC;
        else if (b == P13_ESC_FE) resp_raw[resp_pos++] = P13_STOP;
        else if (b == P13_ESC_FD) resp_raw[resp_pos++] = P13_START;
        else {
          resp_pos = 0;
          state = 0;
          break;
        }
        state = 1;
        break;
    }
  }

  if (!done || resp_pos < 4) return -1;

  uint16_t calc = prox13_fcs(resp_raw, resp_pos - 2);
  uint16_t recv = resp_raw[resp_pos - 2] | (resp_raw[resp_pos - 1] << 8);
  if (calc != recv) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
            "FCS mismatch (calc=%04X recv=%04X)", calc, recv);
    return -1;
  }

  uint8_t id = resp_raw[0];
  uint8_t cmd = resp_raw[1];
  size_t payload_len = resp_pos - 4;
  if (payload_len > out_max) return -1;

  if (out_id)  *out_id  = id;
  if (out_cmd) *out_cmd = cmd;
  if (out_payload && out_len) {
    memcpy(out_payload, &resp_raw[2], payload_len);
    *out_len = payload_len;
  }
  return 0;
}

/* ---------- Transceive command ---------- */
static int
prox13_transceive(nfc_device *pnd, uint8_t cmd,
                  const uint8_t *tx_data, size_t tx_len,
                  uint8_t *rx_data, size_t *rx_len,
                  size_t rx_max, int timeout)
{
  struct prox13_data *d = DRIVER_DATA(pnd);

  d->frame_id++;
  uint8_t expected_id = d->frame_id;

  if (prox13_send_frame(pnd, expected_id, cmd, tx_data, tx_len, timeout) < 0) {
    pnd->last_error = NFC_EIO;
    return pnd->last_error;
  }

  int total_ms = (timeout > 0) ? timeout : 1000;
  int elapsed = 0;

  while (elapsed < total_ms) {
    uint8_t  resp_id = 0;
    uint8_t  resp_cmd = 0;
    uint8_t  payload[P13_MAX_RAW];
    size_t   payload_len = 0;

    int r = prox13_recv_frame(pnd, &resp_id, &resp_cmd,
                              payload, &payload_len,
                              sizeof(payload), total_ms - elapsed);
    if (r < 0) {
      elapsed = total_ms;
      break;
    }

    if (resp_id != expected_id) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
              "Stale frame: id=%02X (expected %02X), cmd=%02X — skip",
              resp_id, expected_id, resp_cmd);
      elapsed += 20;
      continue;
    }

    if (resp_cmd == P13_NOT_READY) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
              "Reader not ready (cmd=0x%02X)", cmd);
      elapsed += 50;
      continue;
    }

    if (resp_cmd == P13_ACK_CODE && cmd != P13_ACK_CODE) {
      if (payload_len >= 1 && rx_data && rx_len) {
        rx_data[0] = payload[0];
        *rx_len = 1;
      } else if (rx_len) {
        *rx_len = 0;
      }
      return NFC_SUCCESS;
    }

    if (resp_cmd != cmd) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
              "Command mismatch: sent %02X, got %02X", cmd, resp_cmd);
      elapsed += 20;
      continue;
    }

    if (payload_len > rx_max) {
      pnd->last_error = NFC_EOVFLOW;
      return pnd->last_error;
    }
    if (rx_data && rx_len) {
      memcpy(rx_data, payload, payload_len);
      *rx_len = payload_len;
    }
    return NFC_SUCCESS;
  }

  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
          "RX timeout (cmd 0x%02X)", cmd);
  uart_flush_input(d->port, true);
  pnd->last_error = NFC_ETIMEOUT;
  return pnd->last_error;
}

/* ---------- scan ---------- */
static size_t
prox13_scan(const nfc_context *context, nfc_connstring connstrings[], const size_t connstrings_len)
{
  (void)context;
  size_t device_found = 0;
  char **ports = uart_list_ports();
  if (!ports) return 0;

  for (int i = 0; ports[i]; i++) {
    serial_port sp = uart_open(ports[i]);
    if (sp == INVALID_SERIAL_PORT || sp == CLAIMED_SERIAL_PORT)
      continue;

    uart_flush_input(sp, true);
    uart_set_speed(sp, PROX13_DEFAULT_SPEED);
    prox13_sleep_ms(500);

    bool detected = false;
    for (int attempt = 0; attempt < 3 && !detected; attempt++) {
      uint8_t raw[4];
      raw[0] = (uint8_t)(0x10 + attempt);
      raw[1] = P13_CMD_DEVICE_HEADER;
      uint16_t fcs = prox13_fcs(raw, 2);
      raw[2] = fcs & 0xFF;
      raw[3] = (fcs >> 8) & 0xFF;

      uint8_t wire[16];
      size_t wpos = 0;
      wire[wpos++] = P13_START;
      for (int k = 0; k < 4; k++) {
        if (raw[k] == P13_START)      { wire[wpos++] = P13_ESC; wire[wpos++] = P13_ESC_FD; }
        else if (raw[k] == P13_STOP)  { wire[wpos++] = P13_ESC; wire[wpos++] = P13_ESC_FE; }
        else if (raw[k] == P13_ESC)   { wire[wpos++] = P13_ESC; wire[wpos++] = P13_ESC_FF; }
        else wire[wpos++] = raw[k];
      }
      wire[wpos++] = P13_STOP;

      uart_flush_input(sp, true);
      uart_send(sp, wire, wpos, 200);

      uint8_t resp[64];
      int got = uart_receive(sp, resp, sizeof(resp), NULL, 500);
      if (got == 0 && resp[0] == P13_START && resp[1] != P13_NOT_READY) {
        detected = true;
      } else {
        prox13_sleep_ms(200);
      }
    }

    uart_close(sp);

    if (detected) {
      nfc_connstring cs;
      snprintf(cs, sizeof(nfc_connstring), "%s:%s:%u",
               PROX13_DRIVER_NAME, ports[i], PROX13_DEFAULT_SPEED);
      memcpy(connstrings[device_found], cs, sizeof(nfc_connstring));
      device_found++;
      if (device_found >= connstrings_len) break;
    }
  }

  for (int i = 0; ports[i]; i++) free(ports[i]);
  free(ports);
  return device_found;
}

/* ---------- open ---------- */
static nfc_device *
prox13_open(const nfc_context *context, const nfc_connstring connstring)
{
  char     port[256] = { 0 };
  uint32_t speed = PROX13_DEFAULT_SPEED;

  const char *p = connstring;
  if (strncmp(p, PROX13_DRIVER_NAME ":", strlen(PROX13_DRIVER_NAME) + 1) == 0)
    p += strlen(PROX13_DRIVER_NAME) + 1;

  const char *colon = strchr(p, ':');
  if (colon) {
    size_t plen = colon - p;
    if (plen >= sizeof(port)) plen = sizeof(port) - 1;
    memcpy(port, p, plen);
    port[plen] = 0;
    speed = strtoul(colon + 1, NULL, 10);
  } else {
    strncpy(port, p, sizeof(port) - 1);
  }
  if (port[0] == 0) return NULL;

  serial_port sp = uart_open(port);
  if (sp == INVALID_SERIAL_PORT) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "Invalid port: %s", port);
    return NULL;
  }
  if (sp == CLAIMED_SERIAL_PORT) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "Port already in use: %s", port);
    return NULL;
  }
  uart_flush_input(sp, true);
  uart_set_speed(sp, speed);

  nfc_device *pnd = nfc_device_new(context, connstring);
  if (!pnd) { uart_close(sp); return NULL; }
  snprintf(pnd->name, sizeof(pnd->name), "%s:%s", PROX13_DRIVER_NAME, port);

  pnd->driver_data = calloc(1, sizeof(struct prox13_data));
  if (!pnd->driver_data) {
    uart_close(sp);
    nfc_device_free(pnd);
    return NULL;
  }
  DRIVER_DATA(pnd)->port     = sp;
  DRIVER_DATA(pnd)->frame_id = 1;
  DRIVER_DATA(pnd)->has_cached_target = false;
  DRIVER_DATA(pnd)->pcb_ns = 0;
  pnd->driver = &prox13_driver;

  uint8_t  resp[64];
  size_t   rlen = 0;
  int      ok = 0;

  prox13_sleep_ms(500);

  for (int attempt = 0; attempt < 8 && !ok; attempt++) {
    if (attempt > 0) {
      prox13_sleep_ms(300);
      uart_flush_input(sp, true);
    }
    if (prox13_transceive(pnd, P13_CMD_DEVICE_HEADER, NULL, 0,
                          resp, &rlen, sizeof(resp), 500) == NFC_SUCCESS &&
        rlen >= 20) {
      ok = 1;
    }
  }

  if (!ok) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,
            "PROX reader not responding on %s", port);
    uart_close(sp);
    pnd->driver_data = NULL;
    nfc_device_free(pnd);
    return NULL;
  }

  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_INFO,
          "PROX reader opened on %s at %u baud", port, speed);
  return pnd;
}

/* ---------- close ---------- */
static void
prox13_close(nfc_device *pnd)
{
  if (!pnd) return;
  struct prox13_data *d = DRIVER_DATA(pnd);
  if (d) {
    if (d->port && d->port != INVALID_SERIAL_PORT && d->port != CLAIMED_SERIAL_PORT) {
      uint8_t resp[8]; size_t rlen = 0;
      prox13_transceive(pnd, P13_CMD_POWER_CTRL, NULL, 0,
                        resp, &rlen, sizeof(resp), 200);
      uart_close(d->port);
      d->port = NULL;
    }
    pnd->driver_data = NULL;
    free(d);
  }
  nfc_device_free(pnd);
}

/* ---------- initiator_init ---------- */
static int
prox13_initiator_init(nfc_device *pnd)
{
  uint8_t resp[8]; size_t rlen = 0;
  if (prox13_transceive(pnd, P13_CMD_PUMP_RESET, NULL, 0,
                        resp, &rlen, sizeof(resp), 500) != NFC_SUCCESS)
    return pnd->last_error;
  if (rlen == 1 && resp[0] != P13_STATUS_OK) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_INFO,
            "Pump reset returned status 0x%02X", resp[0]);
  }
  DRIVER_DATA(pnd)->has_cached_target = false;
  DRIVER_DATA(pnd)->pcb_ns = 0;
  return NFC_SUCCESS;
}

/* ---------- select passive target ---------- */
static int
prox13_initiator_select_passive_target(nfc_device *pnd,
                                       const nfc_modulation nm,
                                       const uint8_t *pbtInitData, const size_t szInitData,
                                       nfc_target *pnt)
{
  struct prox13_data *d = DRIVER_DATA(pnd);
  (void)pbtInitData; (void)szInitData;

  if (nm.nmt != NMT_ISO14443A) {
    pnd->last_error = NFC_EDEVNOTSUPP;
    return pnd->last_error;
  }

  if (d->has_cached_target) {
    *pnt = d->cached_target;
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
            "select_passive_target: returning cached target");
    return 1;
  }

  uint8_t buf[64];
  size_t  blen = 0;
  uint8_t params = 0x80;
  if (prox13_transceive(pnd, P13_CMD_REQ_ANTICOLL, &params, 1,
                        buf, &blen, sizeof(buf), 1000) != NFC_SUCCESS)
    return pnd->last_error;

  if (blen == 1 && buf[0] != P13_STATUS_OK) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
            "No card (status 0x%02X)", buf[0]);
    pnd->last_error = NFC_ETIMEOUT;
    return pnd->last_error;
  }

  if (blen < 7) {
    pnd->last_error = NFC_ERFTRANS;
    return pnd->last_error;
  }

  memset(pnt, 0, sizeof(*pnt));
  pnt->nm = nm;
  pnt->nti.nai.abtAtqa[0] = buf[0];
  pnt->nti.nai.abtAtqa[1] = buf[1];
  pnt->nti.nai.btSak     = buf[2];
  size_t uid_len = blen - 3;
  if (uid_len > sizeof(pnt->nti.nai.abtUid))
    uid_len = sizeof(pnt->nti.nai.abtUid);
  memcpy(pnt->nti.nai.abtUid, &buf[3], uid_len);
  pnt->nti.nai.szUidLen = uid_len;
  pnt->nti.nai.szAtsLen = 0;

  if (pnt->nti.nai.btSak & 0x20) {
    uint8_t body[3];
    body[0] = 0x01;
    body[1] = 0xE0;
    body[2] = 0x70;

    uint8_t ats_raw[64];
    size_t  ats_len = 0;

    if (prox13_transceive(pnd, P13_CMD_TRANSCEIVE_A, body, 3,
                          ats_raw, &ats_len, sizeof(ats_raw), 500) == NFC_SUCCESS &&
        ats_len >= 2) {
      if (ats_raw[0] != P13_STATUS_OK && ats_len == 1) {
        log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
                "RATS returned ACK status 0x%02X", ats_raw[0]);
      } else {
        uint8_t tl = ats_raw[0];
        if ((size_t)tl + 1 > ats_len)
          tl = (uint8_t)(ats_len - 1);
        if (tl > sizeof(pnt->nti.nai.abtAts))
          tl = sizeof(pnt->nti.nai.abtAts);
        memcpy(pnt->nti.nai.abtAts, &ats_raw[1], tl);
        pnt->nti.nai.szAtsLen = tl;
        log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
                "ATS (%u bytes, TL=%u): %02X %02X %02X %02X %02X",
                (unsigned)ats_len, tl,
                tl > 0 ? pnt->nti.nai.abtAts[0] : 0,
                tl > 1 ? pnt->nti.nai.abtAts[1] : 0,
                tl > 2 ? pnt->nti.nai.abtAts[2] : 0,
                tl > 3 ? pnt->nti.nai.abtAts[3] : 0,
                tl > 4 ? pnt->nti.nai.abtAts[4] : 0);
      }
    }
    prox13_sleep_ms(50);
  }

  d->cached_target = *pnt;
  d->has_cached_target = true;
  d->pcb_ns = 0;

  return 1;
}

/* ---------- deselect ---------- */
static int
prox13_initiator_deselect_target(nfc_device *pnd)
{
  (void)pnd;
  return NFC_SUCCESS;
}

/* ---------- target_is_present ---------- */
static int
prox13_initiator_target_is_present(nfc_device *pnd, const nfc_target *pnt)
{
  struct prox13_data *d = DRIVER_DATA(pnd);
  (void)pnt;
  if (d->has_cached_target)
    return NFC_SUCCESS;
  return NFC_ETGRELEASED;
}

/* ---------- MIFARE Classic: трансляция в нативные команды PROX ----------
 * Возвращает 1, если команда распознана и обработана; 0 — не MIFARE-команда. */
static int
prox13_mifare_translate(nfc_device *pnd,
                        const uint8_t *pbtTx, const size_t szTx,
                        uint8_t *pbtRx, const size_t szRx, int timeout)
{
  uint8_t first = pbtTx[0];
  uint8_t body[32];
  size_t  body_len = 0;
  uint8_t prox_cmd = 0;
  int expect_ack = 0;

  switch (first) {
    case 0x60: /* Auth Key A */
    case 0x61: /* Auth Key B */
      if (szTx < 8) { pnd->last_error = NFC_EINVARG; return 1; }
      prox_cmd = P13_CMD_MIFARE_AUTH;
      body[0]  = (first == 0x61) ? 0x03 : 0x02;
      body[1]  = pbtTx[1];
      memcpy(&body[2], &pbtTx[2], 6);
      body_len = 8;
      break;

    case 0x30: /* Read 16 */
      if (szTx < 2) { pnd->last_error = NFC_EINVARG; return 1; }
      prox_cmd = P13_CMD_MIFARE_READ16;
      body[0] = pbtTx[1];
      body_len = 1;
      break;

    case 0xA0: /* Write 16 */
      if (szTx < 18) { pnd->last_error = NFC_EINVARG; return 1; }
      prox_cmd = P13_CMD_MIFARE_WRITE16;
      body[0] = pbtTx[1];
      memcpy(&body[1], &pbtTx[2], 16);
      body_len = 17;
      expect_ack = 1;
      break;

    case 0xA2: /* Write 4 */
      if (szTx < 6) { pnd->last_error = NFC_EINVARG; return 1; }
      prox_cmd = P13_CMD_MIFARE_WRITE4;
      body[0] = pbtTx[1];
      memcpy(&body[1], &pbtTx[2], 4);
      body_len = 5;
      expect_ack = 1;
      break;

    case 0xC0: /* Increment */
      if (szTx < 6) { pnd->last_error = NFC_EINVARG; return 1; }
      prox_cmd = P13_CMD_MIFARE_INCR;
      body[0] = pbtTx[1];
      memcpy(&body[1], &pbtTx[2], 4);
      body_len = 5;
      expect_ack = 1;
      break;

    case 0xC1: /* Decrement */
      if (szTx < 6) { pnd->last_error = NFC_EINVARG; return 1; }
      prox_cmd = P13_CMD_MIFARE_DECR;
      body[0] = pbtTx[1];
      memcpy(&body[1], &pbtTx[2], 4);
      body_len = 5;
      expect_ack = 1;
      break;

    case 0xB0: /* Transfer */
      if (szTx < 2) { pnd->last_error = NFC_EINVARG; return 1; }
      prox_cmd = P13_CMD_MIFARE_TRANSFER;
      body[0] = pbtTx[1];
      body_len = 1;
      expect_ack = 1;
      break;

    case 0xC2: /* Restore */
      if (szTx < 2) { pnd->last_error = NFC_EINVARG; return 1; }
      prox_cmd = P13_CMD_MIFARE_RESTORE;
      body[0] = pbtTx[1];
      body_len = 1;
      expect_ack = 1;
      break;

    default:
      return 0;   /* не MIFARE-команда */
  }

  uint8_t buf[64];
  size_t  blen = 0;
  int r = prox13_transceive(pnd, prox_cmd, body, body_len,
                            buf, &blen, sizeof(buf),
                            (timeout > 0) ? timeout : 1000);
  if (r != NFC_SUCCESS) return 1;

  if (expect_ack) {
    if (blen == 1 && buf[0] == P13_STATUS_OK) return 1;
    if (blen == 0) return 1;
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
            "MIFARE cmd 0x%02X: reader returned 0x%02X", first,
            blen ? buf[0] : 0);
    pnd->last_error = NFC_ERFTRANS;
    return 1;
  }

  if (first == 0x60 || first == 0x61) {
    if (blen == 1 && buf[0] == 0x00) return 1;
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
            "MIFARE auth failed (status 0x%02X)", blen ? buf[0] : 0xFF);
    pnd->last_error = NFC_EMFCAUTHFAIL;
    return 1;
  }

  /* Read 16 */
  if (blen == 16) {
    if (blen > szRx) { pnd->last_error = NFC_EOVFLOW; return 1; }
    memcpy(pbtRx, buf, 16);
    pnd->last_error = 16;
    return 1;
  }
  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
          "MIFARE read: unexpected length %zu", blen);
  pnd->last_error = NFC_ERFTRANS;
  return 1;
}

/* ---------- transceive_bytes ---------- */
static int
prox13_initiator_transceive_bytes(nfc_device *pnd,
                                  const uint8_t *pbtTx, const size_t szTx,
                                  uint8_t *pbtRx, const size_t szRx, int timeout)
{
  if (szTx == 0 || szTx > 250) {
    pnd->last_error = NFC_EINVARG;
    return pnd->last_error;
  }

  struct prox13_data *d = DRIVER_DATA(pnd);

  /* Если это MIFARE Classic — транслируем в нативные команды PROX */
  int is_mifare = d->has_cached_target && !(d->cached_target.nti.nai.btSak & 0x20);
  if (is_mifare) {
    uint8_t first = pbtTx[0];
    /* Диапазон команд MIFARE: 0x30, 0x60, 0x61, 0xA0, 0xA2, 0xB0, 0xC0, 0xC1, 0xC2 */
    if (first == 0x30 || first == 0x60 || first == 0x61 ||
        first == 0xA0 || first == 0xA2 || first == 0xB0 ||
        first == 0xC0 || first == 0xC1 || first == 0xC2) {
      int handled = prox13_mifare_translate(pnd, pbtTx, szTx,
                                            pbtRx, szRx, timeout);
      if (handled) {
        /* pnd->last_error установлен:
         *   >= 0 — количество возвращённых байт (для read)
         *   <  0 — код ошибки
         * Для auth и write — 0 (успех) или NFC_EMFCAUTHFAIL/NFC_ERFTRANS.
         * Успех для auth/write возвращаем как 0 байт. */
        if (pnd->last_error == 16) {
          pnd->last_error = 0;
          return 16;
        }
        if (pnd->last_error == 0) {
          return 0;
        }
        return pnd->last_error;
      }
    }
  }

  /* --- ISO14443-4 (DESFire и др.) — универсальная команда 0x4A --- */
  int is_iso14443_4 = 0;
  if (d->has_cached_target && (d->cached_target.nti.nai.btSak & 0x20))
    is_iso14443_4 = 1;

  uint8_t body[252];
  size_t  body_len;

  body[0] = 0x00;
  if (is_iso14443_4) {
    body[1] = 0x02 | (d->pcb_ns & 1);
    d->pcb_ns ^= 1;
    memcpy(&body[2], pbtTx, szTx);
    body_len = 2 + szTx;
  } else {
    memcpy(&body[1], pbtTx, szTx);
    body_len = 1 + szTx;
  }

  uint8_t buf[1024];
  size_t  blen = 0;
  int r = prox13_transceive(pnd, P13_CMD_TRANSCEIVE_A, body, body_len,
                            buf, &blen, sizeof(buf),
                            (timeout > 0) ? timeout : 1000);
  if (r != NFC_SUCCESS) return r;

  if (blen == 1) {
    if (buf[0] == P13_STATUS_OK) return 0;
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG,
            "reader returned status 0x%02X", buf[0]);
    pnd->last_error = NFC_ERFTRANS;
    return pnd->last_error;
  }

  if (blen >= 2) {
    memmove(buf, buf + 1, blen - 1);
    blen--;
  }

  if (blen > szRx) {
    pnd->last_error = NFC_EOVFLOW;
    return pnd->last_error;
  }
  if (blen > 0) {
    memcpy(pbtRx, buf, blen);
  }
  return (int)blen;
}

/* ---------- abort ---------- */
static int
prox13_abort_command(nfc_device *pnd)
{
  (void)pnd;
  return NFC_SUCCESS;
}

/* ---------- idle ---------- */
static int
prox13_idle(nfc_device *pnd)
{
  uint8_t resp[8]; size_t rlen = 0;
  prox13_transceive(pnd, P13_CMD_PUMP_OFF, NULL, 0,
                    resp, &rlen, sizeof(resp), 500);
  DRIVER_DATA(pnd)->has_cached_target = false;
  return NFC_SUCCESS;
}

/* ---------- powerdown ---------- */
static int
prox13_powerdown(nfc_device *pnd)
{
  uint8_t resp[8]; size_t rlen = 0;
  prox13_transceive(pnd, P13_CMD_POWER_CTRL, NULL, 0,
                    resp, &rlen, sizeof(resp), 500);
  DRIVER_DATA(pnd)->has_cached_target = false;
  return NFC_SUCCESS;
}

/* ---------- stubs ---------- */
static int
prox13_set_property_bool(nfc_device *pnd, const nfc_property property, const bool bEnable)
{
  switch (property) {
    case NP_INFINITE_SELECT:
      pnd->bInfiniteSelect = bEnable;
      break;
    default:
      break;
  }
  return NFC_SUCCESS;
}

static int
prox13_set_property_int(nfc_device *pnd, const nfc_property property, const int value)
{
  (void)pnd; (void)property; (void)value;
  return NFC_SUCCESS;
}

static int
prox13_get_supported_modulation(nfc_device *pnd, const nfc_mode mode,
                                const nfc_modulation_type **const supported_mt)
{
  (void)pnd;
  static const nfc_modulation_type init_mt[] = {
    NMT_ISO14443A, NMT_ISO14443B, NMT_ISO14443BI, NMT_ISO14443B2CT,
    NMT_ISO14443B2SR, NMT_ISO14443BICLASS, NMT_FELICA, NMT_JEWEL,
    NMT_BARCODE, NMT_DEP, 0
  };
  static const nfc_modulation_type targ_mt[] = { 0 };
  *supported_mt = (mode == N_INITIATOR) ? init_mt : targ_mt;
  return NFC_SUCCESS;
}

static int
prox13_get_supported_baud_rate(nfc_device *pnd, const nfc_mode mode,
                               const nfc_modulation_type nmt,
                               const nfc_baud_rate **const supported_br)
{
  (void)pnd; (void)mode; (void)nmt;
  static const nfc_baud_rate br[] = { NBR_106, NBR_212, NBR_424, NBR_847, 0 };
  *supported_br = br;
  return NFC_SUCCESS;
}

static int
prox13_get_information_about(nfc_device *pnd, char **buf)
{
  (void)pnd;
  *buf = strdup("PROX 13 MHz Reader driver");
  return (int)strlen(*buf);
}

static const char *
prox13_strerror(const nfc_device *pnd)
{
  return nfc_strerror(pnd);
}

/* ---------- Driver structure ---------- */
const struct nfc_driver prox13_driver = {
  .name      = PROX13_DRIVER_NAME,
  .scan_type = INTRUSIVE,
  .scan      = prox13_scan,
  .open      = prox13_open,
  .close     = prox13_close,
  .strerror  = prox13_strerror,

  .initiator_init                   = prox13_initiator_init,
  .initiator_init_secure_element    = NULL,
  .initiator_select_passive_target  = prox13_initiator_select_passive_target,
  .initiator_poll_target            = NULL,
  .initiator_select_dep_target      = NULL,
  .initiator_deselect_target        = prox13_initiator_deselect_target,
  .initiator_transceive_bytes       = prox13_initiator_transceive_bytes,
  .initiator_transceive_bits        = NULL,
  .initiator_transceive_bytes_timed = NULL,
  .initiator_transceive_bits_timed  = NULL,
  .initiator_target_is_present      = prox13_initiator_target_is_present,

  .target_init           = NULL,
  .target_send_bytes     = NULL,
  .target_receive_bytes  = NULL,
  .target_send_bits      = NULL,
  .target_receive_bits   = NULL,

  .device_set_property_bool     = prox13_set_property_bool,
  .device_set_property_int      = prox13_set_property_int,
  .get_supported_modulation     = prox13_get_supported_modulation,
  .get_supported_baud_rate      = prox13_get_supported_baud_rate,
  .device_get_information_about = prox13_get_information_about,

  .abort_command  = prox13_abort_command,
  .idle           = prox13_idle,
  .powerdown      = prox13_powerdown,
};