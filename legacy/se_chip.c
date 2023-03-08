#include "se_chip.h"
#include <stdbool.h>
#include <stdint.h>

#include "mi2c.h"

#include "aes/aes.h"
#include "bip32.h"
#include "mi2c.h"
#include "rand.h"
#include "secbool.h"
#include "sys.h"
#include "util.h"
#include "flash.h"
#include "memzero.h"

#define APP (0x01 << 8)

#define SE_NEEDSBACKUP (7 | APP)   // byte
#define SE_INITIALIZED (14 | APP)  // byte
#define SE_PIN (20 | APP)          // uint32
#define SE_PINFLAG (21 | APP)      // uint32
#define SE_VERIFYPIN (22 | APP)    // uint32
#define SE_RESET (27 | APP)
#define SE_SEEDSTRENGTH (30 | APP)  // uint32
#define SE_U2FCOUNTER (9 | APP)     // uint32
#define SE_MNEMONIC (2 | APP)       // string(241)
#define SE_PIN_RETRY_MAX 16

static uint32_t se_pin_failed_counter = 0;

uint8_t g_ucSessionKey[SESSION_KEYLEN];

const char NIST256P1[] = "nist256p1";

// const uint8_t SessionModeMode_ROMKEY[16] = {0x80, 0xBA, 0x15, 0x37, 0xD2,
// 0x84,
//                                             0x8D, 0x64, 0xA7, 0xB4, 0x58,
//                                             0xF4, 0x58, 0xFE, 0xD8, 0x84};

// const uint8_t ucDefaultSessionKey[16] = {0x97, 0x1e, 0xaa, 0x62, 0xbf, 0xb1,
//                                          0xfe, 0xb6, 0x99, 0x88, 0x0a, 0xb2,
//                                          0xdb, 0x59, 0x88, 0x59};

extern void config_setSeSessionKey(const uint8_t *data, uint32_t size);
extern bool config_getSeSessionKey(uint8_t *dest, uint16_t dest_size);

bool randomBuf_SE(uint8_t *ucRandom, uint8_t ucLen) {
  uint8_t ucRandomCmd[5] = {0x00, 0x84, 0x00, 0x00, 0x00}, ucTempBuf[32];
  uint16_t usLen;

  ucRandomCmd[4] = ucLen;
  usLen = sizeof(ucTempBuf);
  if (!bMI2CDRV_SendData(ucRandomCmd, sizeof(ucRandomCmd))) {
    return false;
  }
  if (!bMI2CDRV_ReceiveData(ucTempBuf, &usLen)) {
    return false;
  }
  memcpy(ucRandom, ucTempBuf, ucLen);
  return true;
}

void random_buffer_ST(uint8_t *buf, size_t len) {
  uint32_t r = 0;
  for (size_t i = 0; i < len; i++) {
    if (i % 4 == 0) {
      r = random32();
    }
    buf[i] = (r >> ((i % 4) * 8)) & 0xFF;
  }
}

// TODO
static bool xor_cal(uint8_t *pucSrc1, uint8_t *pucSrc2, uint16_t usLen,
                    uint8_t *pucDest) {
  uint16_t i;

  for (i = 0; i < usLen; i++) {
    pucDest[i] = pucSrc1[i] ^ pucSrc2[i];
  }
  return true;
}

// extern uint32_t _g_sec_session_key_addr[];
/*
 *master i2c synsessionkey
 */
void se_sync_session_key(void) {
  uint8_t r1[16], r2[16], r3[32];
  uint8_t *pDefault_key;  // TODO need read from special flash addr
  uint8_t data_buf[64], hash_buf[32];
  uint8_t sync_cmd[5 + 48] = {0x00, 0xfa, 0x00, 0x00, 0x30};
  uint16_t recv_len = 0xff;
  aes_encrypt_ctx en_ctxe;
  aes_decrypt_ctx de_ctxe;

  pDefault_key = flash_read_bytes(DEFAULT_SECKEYADDR);  // DEFAULT_SECKEYADDR
  // memzero(data_buf, sizeof(data_buf));
  // memcpy(data_buf, pDefault_key, 16);
  // get random from se
  randomBuf_SE(r1, 16);
  // get random itself
  random_buffer_ST(r2, 16);
  // cal tmp sessionkey with x hash256
  memzero(data_buf, sizeof(data_buf));
  xor_cal(r1, r2, sizeof(r1), data_buf);
  hasher_Raw(HASHER_SHA2, data_buf, 16, hash_buf);
  // use session key organization data1
  memcpy(g_ucSessionKey, hash_buf, 16);
  aes_encrypt_key128(g_ucSessionKey, &en_ctxe);
  aes_ecb_encrypt(r1, data_buf, sizeof(r1), &en_ctxe);
  // organization data2
  memcpy(r3, r1, sizeof(r1));
  memcpy(r3 + sizeof(r1), r2, sizeof(r2));
  aes_encrypt_key128(pDefault_key, &en_ctxe);
  aes_ecb_encrypt(r3, data_buf + 16, sizeof(r1) + sizeof(r2), &en_ctxe);
  // send data1 + data2 to se and recv returned result
  memcpy(sync_cmd + 5, data_buf, 48);
  if (MI2C_OK !=
      se_transmit_plain(sync_cmd, sizeof(sync_cmd), data_buf, &recv_len)) {
    memset(g_ucSessionKey, 0x00, SESSION_KEYLEN);
  }

  // handle the returned data
  aes_decrypt_key128(g_ucSessionKey, &de_ctxe);
  aes_ecb_decrypt(data_buf, r3, recv_len, &de_ctxe);
  if (memcmp(r2, r3, sizeof(r2)) != 0) {
    memset(g_ucSessionKey, 0x00, SESSION_KEYLEN);
  }
}

/*
 *master i2c send
 */
uint32_t se_transmit(uint8_t ucCmd, uint8_t ucIndex, uint8_t *pucSendData,
                     uint16_t usSendLen, uint8_t *pucRevData,
                     uint16_t *pusRevLen, uint8_t ucMode, uint8_t ucWRFlag) {
  uint8_t ucRandom[16], i;
  uint16_t usPadLen;
  aes_encrypt_ctx ctxe;
  aes_decrypt_ctx ctxd;
  // se apdu
  if (MI2C_ENCRYPT == ucMode) {
    if ((SET_SESTORE_DATA & ucWRFlag) || (DEVICEINIT_DATA & ucWRFlag)) {
      // data aes encrypt
      randomBuf_SE(ucRandom, sizeof(ucRandom));
      memset(&ctxe, 0, sizeof(aes_encrypt_ctx));
      aes_encrypt_key128(g_ucSessionKey, &ctxe);
      memcpy(SH_IOBUFFER, ucRandom, sizeof(ucRandom));
      memcpy(SH_IOBUFFER + sizeof(ucRandom), pucSendData, usSendLen);
      usSendLen += sizeof(ucRandom);
      // add pad
      if (usSendLen % AES_BLOCK_SIZE) {
        usPadLen = AES_BLOCK_SIZE - (usSendLen % AES_BLOCK_SIZE);
        memset(SH_IOBUFFER + usSendLen, 0x00, usPadLen);
        SH_IOBUFFER[usSendLen] = 0x80;
        usSendLen += usPadLen;
      }
      aes_ecb_encrypt(SH_IOBUFFER, g_ucMI2cRevBuf, usSendLen, &ctxe);
    } else {
      // data add random
      random_buffer_ST(ucRandom, sizeof(ucRandom));
      memcpy(g_ucMI2cRevBuf, ucRandom, sizeof(ucRandom));
      if (usSendLen > 0) {
        memcpy(g_ucMI2cRevBuf + sizeof(ucRandom), pucSendData, usSendLen);
      }
      usSendLen += sizeof(ucRandom);
    }
  }

  CLA = 0x80;
  INS = ucCmd;
  P1 = ucIndex;
  P2 = ucWRFlag | ucMode;
  if (usSendLen > 255) {
    P3 = 0x00;
    SH_IOBUFFER[0] = (usSendLen >> 8) & 0xFF;
    SH_IOBUFFER[1] = usSendLen & 0xFF;
    if (usSendLen > (MI2C_BUF_MAX_LEN - 7)) {
      return MI2C_ERROR;
    }
    if (MI2C_ENCRYPT == ucMode) {
      memcpy(SH_IOBUFFER + 2, g_ucMI2cRevBuf, usSendLen);
    } else {
      memcpy(SH_IOBUFFER + 2, pucSendData, usSendLen);
    }

    usSendLen += 7;
  } else {
    P3 = usSendLen & 0xFF;
    if (MI2C_ENCRYPT == ucMode) {
      memcpy(SH_IOBUFFER, g_ucMI2cRevBuf, usSendLen);
    } else {
      memcpy(SH_IOBUFFER, pucSendData, usSendLen);
    }
    usSendLen += 5;
  }
  if (false == bMI2CDRV_SendData(SH_CMDHEAD, usSendLen)) {
    return MI2C_ERROR;
  }
  g_usMI2cRevLen = sizeof(g_ucMI2cRevBuf);
  if (false == bMI2CDRV_ReceiveData(g_ucMI2cRevBuf, &g_usMI2cRevLen)) {
    if (g_usMI2cRevLen && pucRevData) {
      *pusRevLen = *pusRevLen > g_usMI2cRevLen ? g_usMI2cRevLen : *pusRevLen;
      memcpy(pucRevData, g_ucMI2cRevBuf, *pusRevLen);
    }
    return MI2C_ERROR;
  }
  if (MI2C_ENCRYPT == ucMode) {
    // aes dencrypt data
    if ((GET_SESTORE_DATA == ucWRFlag) && (g_usMI2cRevLen > 0) &&
        ((g_usMI2cRevLen % 16 == 0x00))) {
      memset(&ctxd, 0, sizeof(aes_decrypt_ctx));
      aes_decrypt_key128(g_ucSessionKey, &ctxd);
      aes_ecb_decrypt(g_ucMI2cRevBuf, SH_IOBUFFER, g_usMI2cRevLen, &ctxd);

      if (memcmp(SH_IOBUFFER, ucRandom, sizeof(ucRandom)) != 0) {
        return MI2C_ERROR;
      }
      // delete pad
      for (i = 1; i < 0x11; i++) {
        if (SH_IOBUFFER[g_usMI2cRevLen - i] == 0x80) {
          for (usPadLen = 1; usPadLen < i; usPadLen++) {
            if (SH_IOBUFFER[g_usMI2cRevLen - usPadLen] != 0x00) {
              i = 0x11;
              break;
            }
          }
          break;
        }
      }

      if (i != 0x11) {
        g_usMI2cRevLen = g_usMI2cRevLen - i;
      }
      g_usMI2cRevLen -= sizeof(ucRandom);
      if (pucRevData != NULL) {
        memcpy(pucRevData, SH_IOBUFFER + sizeof(ucRandom), g_usMI2cRevLen);
        *pusRevLen = g_usMI2cRevLen;
        return MI2C_OK;
      }
    }
  }
  if (pucRevData != NULL) {
    memcpy(pucRevData, g_ucMI2cRevBuf, g_usMI2cRevLen);
    *pusRevLen = g_usMI2cRevLen;
    ;
  }
  return MI2C_OK;
}

uint32_t se_transmit_ex(uint8_t ucCmd, uint8_t ucIndex, uint8_t *pucSendData,
                        uint16_t usSendLen, uint8_t *pucRevData,
                        uint16_t *pusRevLen, uint8_t ucMode, uint8_t ucWRFlag,
                        bool bFirst) {
  uint8_t ucRandom[16], i;
  uint16_t usPadLen;
  aes_encrypt_ctx ctxe;
  aes_decrypt_ctx ctxd;
  // se apdu
  if (MI2C_ENCRYPT == ucMode) {
    if ((SET_SESTORE_DATA & ucWRFlag) || (DEVICEINIT_DATA & ucWRFlag)) {
      // data aes encrypt
      randomBuf_SE(ucRandom, sizeof(ucRandom));
      memset(&ctxe, 0, sizeof(aes_encrypt_ctx));
      aes_encrypt_key128(g_ucSessionKey, &ctxe);
      memcpy(SH_IOBUFFER, ucRandom, sizeof(ucRandom));
      memcpy(SH_IOBUFFER + sizeof(ucRandom), pucSendData, usSendLen);
      usSendLen += sizeof(ucRandom);
      // add pad
      if (usSendLen % AES_BLOCK_SIZE) {
        usPadLen = AES_BLOCK_SIZE - (usSendLen % AES_BLOCK_SIZE);
        memset(SH_IOBUFFER + usSendLen, 0x00, usPadLen);
        SH_IOBUFFER[usSendLen] = 0x80;
        usSendLen += usPadLen;
      }
      aes_ecb_encrypt(SH_IOBUFFER, g_ucMI2cRevBuf, usSendLen, &ctxe);
    } else {
      // data add random
      random_buffer_ST(ucRandom, sizeof(ucRandom));
      memcpy(g_ucMI2cRevBuf, ucRandom, sizeof(ucRandom));
      if (usSendLen > 0) {
        memcpy(g_ucMI2cRevBuf + sizeof(ucRandom), pucSendData, usSendLen);
      }
      usSendLen += sizeof(ucRandom);
    }
  }
  if (bFirst)
    CLA = 0x80;
  else
    CLA = 0x90;
  INS = ucCmd;
  P1 = ucIndex;
  P2 = ucWRFlag | ucMode;
  if (usSendLen > 255) {
    P3 = 0x00;
    SH_IOBUFFER[0] = (usSendLen >> 8) & 0xFF;
    SH_IOBUFFER[1] = usSendLen & 0xFF;
    if (usSendLen > (MI2C_BUF_MAX_LEN - 7)) {
      return MI2C_ERROR;
    }
    if (MI2C_ENCRYPT == ucMode) {
      memcpy(SH_IOBUFFER + 2, g_ucMI2cRevBuf, usSendLen);
    } else {
      memcpy(SH_IOBUFFER + 2, pucSendData, usSendLen);
    }

    usSendLen += 7;
  } else {
    P3 = usSendLen & 0xFF;
    if (MI2C_ENCRYPT == ucMode) {
      memcpy(SH_IOBUFFER, g_ucMI2cRevBuf, usSendLen);
    } else {
      memcpy(SH_IOBUFFER, pucSendData, usSendLen);
    }
    usSendLen += 5;
  }
  if (false == bMI2CDRV_SendData(SH_CMDHEAD, usSendLen)) {
    return MI2C_ERROR;
  }
  g_usMI2cRevLen = sizeof(g_ucMI2cRevBuf);
  if (false == bMI2CDRV_ReceiveData(g_ucMI2cRevBuf, &g_usMI2cRevLen)) {
    if (g_usMI2cRevLen && pucRevData) {
      *pusRevLen = *pusRevLen > g_usMI2cRevLen ? g_usMI2cRevLen : *pusRevLen;
      memcpy(pucRevData, g_ucMI2cRevBuf, *pusRevLen);
    }
    return MI2C_ERROR;
  }
  if (MI2C_ENCRYPT == ucMode) {
    // aes dencrypt data
    if ((GET_SESTORE_DATA == ucWRFlag) && (g_usMI2cRevLen > 0) &&
        ((g_usMI2cRevLen % 16 == 0x00))) {
      memset(&ctxd, 0, sizeof(aes_decrypt_ctx));
      aes_decrypt_key128(g_ucSessionKey, &ctxd);
      aes_ecb_decrypt(g_ucMI2cRevBuf, SH_IOBUFFER, g_usMI2cRevLen, &ctxd);

      if (memcmp(SH_IOBUFFER, ucRandom, sizeof(ucRandom)) != 0) {
        return MI2C_ERROR;
      }
      // delete pad
      for (i = 1; i < 0x11; i++) {
        if (SH_IOBUFFER[g_usMI2cRevLen - i] == 0x80) {
          for (usPadLen = 1; usPadLen < i; usPadLen++) {
            if (SH_IOBUFFER[g_usMI2cRevLen - usPadLen] != 0x00) {
              i = 0x11;
              break;
            }
          }
          break;
        }
      }

      if (i != 0x11) {
        g_usMI2cRevLen = g_usMI2cRevLen - i;
      }
      g_usMI2cRevLen -= sizeof(ucRandom);
      if (pucRevData != NULL) {
        memcpy(pucRevData, SH_IOBUFFER + sizeof(ucRandom), g_usMI2cRevLen);
        *pusRevLen = g_usMI2cRevLen;
        return MI2C_OK;
      }
    }
  }
  if (pucRevData != NULL) {
    memcpy(pucRevData, g_ucMI2cRevBuf, g_usMI2cRevLen);
    *pusRevLen = g_usMI2cRevLen;
    ;
  }
  return MI2C_OK;
}

uint32_t se_transmit_plain(uint8_t *pucSendData, uint16_t usSendLen,
                           uint8_t *pucRevData, uint16_t *pusRevLen) {
  if (false == bMI2CDRV_SendData(pucSendData, usSendLen)) {
    return MI2C_ERROR;
  }
  if (false == bMI2CDRV_ReceiveData(pucRevData, pusRevLen)) {
    return MI2C_ERROR;
  }
  return MI2C_OK;
}

// mode is export seed
void se_get_seed(bool mode, const char *passphrase, uint8_t *seed) {
  uint8_t cmd[1024];
  uint16_t resplen;
  int passphraselen = 0;
  uint8_t salt[256] = {0};
  if (passphrase) {
    passphraselen = strnlen(passphrase, 256);
    memcpy(salt, passphrase, passphraselen);
  }

  cmd[0] = mode;
  // salt LV
  cmd[1] = (passphraselen)&0xFF;
  cmd[2] = (passphraselen >> 8) & 0xFF;
  memcpy(cmd + 3, salt, passphraselen);
  se_transmit(MI2C_CMD_WR_PIN, MNEMONIC_INDEX_TOSEED, cmd, passphraselen + 3,
              seed, &resplen, MI2C_ENCRYPT, SET_SESTORE_DATA);
  return;
}

bool se_ecdsa_get_pubkey(uint32_t *address, uint8_t count, uint8_t *pubkey) {
  uint8_t resp[256];
  uint16_t resp_len;
  if (MI2C_OK != se_transmit(MI2C_CMD_ECC_EDDSA, EDDSA_INDEX_CHILDKEY,
                             (uint8_t *)address, count * 4, resp, &resp_len,
                             MI2C_PLAIN, SET_SESTORE_DATA)) {
    return false;
  }
  memcpy(pubkey, resp + 1 + 4 + 32 + 33, 33);
  return true;
}

bool se_set_value(uint16_t key, const void *val_dest, uint16_t len) {
  uint8_t flag = key >> 8;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (key & 0xFF), (uint8_t *)val_dest,
                             len, NULL, 0, (flag & MI2C_PLAIN),
                             SET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool se_get_value(uint16_t key, void *val_dest, uint16_t max_len,
                  uint16_t *len) {
  uint8_t flag = key >> 8;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (key & 0xFF), NULL, 0, val_dest,
                             len, (flag & MI2C_PLAIN), GET_SESTORE_DATA)) {
    return false;
  }
  *len = *len > max_len ? max_len : *len;
  return true;
}

bool se_delete_key(uint16_t key) {
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (key & 0xFF), NULL, 0, NULL, 0,
                             MI2C_PLAIN, DELETE_SESTORE_DATA)) {
    return false;
  }
  return true;
}

void se_reset_storage(void) {
  se_transmit(MI2C_CMD_WR_PIN, (SE_RESET & 0xFF), NULL, 0, NULL, NULL,
              MI2C_ENCRYPT, SET_SESTORE_DATA);
}

bool se_get_sn(char **serial) {
  uint8_t ucSnCmd[5] = {0x00, 0xf5, 0x01, 0x00, 0x10};
  static char sn[32] = {0};
  uint16_t sn_len = sizeof(sn);
  if (MI2C_OK !=
      se_transmit_plain(ucSnCmd, sizeof(ucSnCmd), (uint8_t *)sn, &sn_len)) {
    return false;
  }
  if (sn_len > sizeof(sn)) {
    return false;
  }
  *serial = sn;
  return true;
}
char *_se_get_version(void) {
  uint8_t ucVerCmd[5] = {0x00, 0xf7, 0x00, 00, 0x02};
  uint8_t ver[2] = {0};
  uint16_t ver_len = sizeof(ver);
  static char ver_char[9] = {0};
  int i = 0;

  if (MI2C_OK != se_transmit_plain(ucVerCmd, sizeof(ucVerCmd), ver, &ver_len)) {
    return NULL;
  }

  ver_char[i++] = (ver[0] >> 4) + '0';
  ver_char[i++] = '.';
  ver_char[i++] = (ver[0] & 0x0f) + '0';
  ver_char[i++] = '.';
  ver_char[i++] = (ver[1] >> 4) + '0';
  ver_char[i++] = '.';
  ver_char[i++] = (ver[1] & 0x0f) + '0';

  return ver_char;
}

char *se_get_version(void) {
  char *se_sn = NULL;
  char *se_version = NULL;
  static char fix_version[] = "1.1.0.3";

  se_version = _se_get_version();
  if (se_version) {
    if (strcmp(se_version, "1.1.0.2") == 0) {
      if (se_get_sn(&se_sn)) {
        if (strcmp(se_sn, "Bixin21032201500") > 0) {
          return fix_version;
        }
      }
    }
    return se_version;
  }

  return NULL;
}

bool se_verify(void *message, uint16_t message_len, uint16_t max_len,
               void *cert_val, uint16_t *cert_len, void *signature_val,
               uint16_t *signature_len) {
  /* get cert data */
  uint8_t ucCertCmd[5] = {0x00, 0xf8, 0x01, 0x00, 0x00};
  if (MI2C_OK !=
      se_transmit_plain(ucCertCmd, sizeof(ucCertCmd), cert_val, cert_len)) {
    return false;
  }
  if (*cert_len > max_len) {
    return false;
  }
  if (*signature_len > max_len) {
    return false;
  }

  /* get signature */
  uint8_t ucSignCmd[37] = {0x00, 0x72, 0x00, 00, 0x20};

  if (message_len > 0x20) {
    return false;
  }
  memcpy(ucSignCmd + 5, message, message_len);
  if (MI2C_OK != se_transmit_plain(ucSignCmd, sizeof(ucSignCmd), signature_val,
                                   signature_len)) {
    return false;
  }
  if (*signature_len > max_len) {
    return false;
  }
  return true;
}

bool se_backup(void *val_dest, uint16_t *len) {
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, 0x12, NULL, 0,
                             (uint8_t *)val_dest, len, MI2C_PLAIN,
                             GET_SESTORE_DATA)) {
    return false;
  }
  return true;
}
bool se_restore(void *val_src, uint16_t src_len) {
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, 0x12, val_src, src_len, NULL,
                             NULL, MI2C_PLAIN, DELETE_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool se_device_init(uint8_t mode, const char *passphrase) {
  uint8_t cmd[1024];
  uint16_t passphraselen = 0;

  if (NULL != passphrase) {
    passphraselen = strnlen(passphrase, 256);
  }
  cmd[0] = mode;
  // salt LV
  cmd[1] = passphraselen & 0xFF;
  cmd[2] = (passphraselen >> 8) & 0xFF;
  memcpy(cmd + 3, passphrase, passphraselen);
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, 0x12, cmd, passphraselen + 3,
                             NULL, NULL, MI2C_ENCRYPT, DEVICEINIT_DATA)) {
    return false;
  }
  return true;
}

bool se_st_seed_en(uint16_t key, void *plain_data, uint16_t plain_len,
                   void *cipher_data, uint16_t *cipher_len) {
  uint8_t flag = key >> 8;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (key & 0xFF), plain_data,
                             plain_len, cipher_data, cipher_len,
                             (flag & MI2C_PLAIN), SET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool se_st_seed_de(uint16_t key, void *cipher_data, uint16_t cipher_len,
                   void *plain_data, uint16_t *plain_len) {
  uint8_t flag = key >> 8;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (key & 0xFF), cipher_data,
                             cipher_len, plain_data, plain_len,
                             (flag & MI2C_PLAIN), GET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool st_backup_entory_to_se(uint16_t key, uint8_t *seed, uint8_t seed_len) {
  uint8_t flag = key >> 8;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (key & 0xFF), seed, seed_len,
                             NULL, NULL, (flag & MI2C_PLAIN),
                             SET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool st_restore_entory_from_se(uint16_t key, uint8_t *seed, uint8_t *seed_len) {
  uint8_t flag = key >> 8;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (key & 0xFF), NULL, 0, seed,
                             (uint16_t *)seed_len, (flag & MI2C_PLAIN),
                             GET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool se_isInitialized(void) {
#if FEITIAN_PCB_V1_4
  if (se_isLifecyComSta()) {
    return true;
  }
#else
  uint16_t len;
  uint8_t initialized = 0;
  uint8_t needs_backup = 0;
  se_get_value(SE_NEEDSBACKUP, &needs_backup, 1, &len);
  se_get_value(SE_INITIALIZED, &initialized, sizeof(initialized), &len);

  if (initialized == 1) {
    if (needs_backup == 0) {
      return true;
    } else {
      se_reset_storage();
    }
  }
#endif
  return false;
}

bool se_hasPin(void) {
#if FEITIAN_PCB_V1_4
  return se_isInitialized();
#else
  uint8_t has_pin = 1;
  uint16_t len;
  if (se_get_value(SE_PINFLAG, &has_pin, 1, &len)) {
    if (has_pin == 0) return true;
  }

  return false;
#endif
}

bool se_setPin(uint32_t pin) { return se_set_value(SE_PIN, &pin, sizeof(pin)); }

bool se_verifyPin(uint32_t pin, uint8_t mode) {
  uint8_t retry = 0, work_mode = 0;
  uint16_t len = sizeof(retry);
  // mode : SE_VERIFYPIN_FIRST is first verify pin
  work_mode =
      (mode == SE_VERIFYPIN_FIRST) ? SE_VERIFYPIN_FIRST : SET_SESTORE_DATA;

  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (SE_VERIFYPIN & 0xFF),
                             (uint8_t *)&pin, sizeof(pin), &retry, &len,
                             MI2C_ENCRYPT, work_mode)) {
    se_pin_failed_counter = SE_PIN_RETRY_MAX - retry;
    return false;
  }

  return true;
}

bool se_changePin(uint32_t oldpin, uint32_t newpin) {
  if (!se_verifyPin(oldpin, SE_VERIFYPIN_OTHER)) return false;
  return se_setPin(newpin);
}

uint32_t se_pinFailedCounter(void) { return se_pin_failed_counter; }

// first used it will return false and retry counter
// last will return true
// note : first used mode = SE_GENSEDMNISEC_FIRST
//        other mode =SE_GENSEDMNISEC_OTHER
bool se_setSeed(uint8_t *preCnts, uint8_t mode) {
  bool bIsFirst = true;
  uint16_t recv_len = 0;
  bIsFirst = (mode == SE_GENSEDMNISEC_FIRST) ? true : false;
  if (MI2C_OK != se_transmit_ex(MI2C_CMD_WR_PIN, 0x12, NULL, 0, preCnts,
                                &recv_len, MI2C_ENCRYPT, SE_WRFLG_GENSEED,
                                bIsFirst)) {
    return false;
  }
  return true;
}

bool se_setMinisec(uint8_t *preCnts, uint8_t mode) {
  bool bIsFirst = true;
  uint16_t recv_len = 0;
  bIsFirst = (mode == SE_GENSEDMNISEC_FIRST) ? true : false;
  if (MI2C_OK != se_transmit_ex(MI2C_CMD_WR_PIN, 0x12, NULL, 0, preCnts,
                                &recv_len, MI2C_ENCRYPT, SE_WRFLG_GENMINISECRET,
                                bIsFirst)) {
    return false;
  }
  return true;
}

bool se_setSeedStrength(uint32_t strength) {
  if (strength != 128 && strength != 192 && strength != 256) return false;
  return se_set_value(SE_SEEDSTRENGTH, &strength, sizeof(strength));
}

bool se_getSeedStrength(uint32_t *strength) {
  uint16_t len;
  if (se_get_value(SE_SEEDSTRENGTH, strength, sizeof(uint32_t), &len)) {
    if (*strength == 128 || *strength == 192 || *strength == 256) return true;
  }
  return false;
}

bool se_getNeedsBackup(bool *needs_backup) {
  uint16_t len;
  if (se_get_value(SE_NEEDSBACKUP, needs_backup, 1, &len)) {
    return true;
  }
  return false;
}

bool se_setNeedsBackup(bool needs_backup) {
  return se_set_value(SE_NEEDSBACKUP, &needs_backup, sizeof(needs_backup));
}

bool se_export_seed(uint8_t *seed) {
  uint16_t seed_len = 0;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, SE_EXPORT_SEED, NULL, 0, seed,
                             &seed_len, MI2C_ENCRYPT, GET_SESTORE_DATA)) {
    return false;
  }
  if (seed_len != 64) return false;

  return true;
}

bool se_importSeed(uint8_t *seed) {
  uint8_t data[65];
  data[0] = 2;
  memcpy(data + 1, seed, 64);
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, 0x12, data, 65, NULL, NULL,
                             MI2C_ENCRYPT, SET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool se_isFactoryMode(void) {
  uint8_t cmd[5] = {0x00, 0xf8, 0x04, 00, 0x01};
  uint8_t mode = 0;
  uint16_t len = sizeof(mode);

  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), &mode, &len)) {
    return false;
  }
  if (len == 1 && mode == 0xff) {
    return true;
  }
  return false;
}

bool se_set_u2f_counter(uint32_t u2fcounter) {
  return se_set_value(SE_U2FCOUNTER, &u2fcounter, sizeof(u2fcounter));
}

bool se_get_u2f_counter(uint32_t *u2fcounter) {
  uint16_t len;
  return se_get_value(SE_U2FCOUNTER, u2fcounter, sizeof(uint32_t), &len);
}

bool se_set_mnemonic(const void *mnemonic, uint16_t len) {
  return se_set_value(SE_MNEMONIC, mnemonic, len);
}

bool se_isLifecyComSta(void) {
  uint8_t cmd[5] = {0x00, 0xf8, 0x04, 00, 0x01};
  uint8_t mode = 0;
  uint16_t len = sizeof(mode);

  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), &mode, &len)) {
    return false;
  }
  if (len == 1 && mode == 0x82) {
    return true;
  }
  return false;
}

bool se_sessionStart(uint8_t *session_id_bytes) {
  uint16_t recv_len = 0;  // 32 bytes session id
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_SESSION, 0x00, NULL, 0,
                             session_id_bytes, &recv_len, MI2C_ENCRYPT,
                             GET_SESTORE_DATA)) {
    return false;
  }
  if (recv_len != 32) return false;
  return true;
}

bool se_sessionOpen(uint8_t *session_id_bytes) {
  uint16_t recv_len = 0;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_SESSION, 0x01, session_id_bytes, 32,
                             NULL, &recv_len, MI2C_ENCRYPT, SET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool se_sessionGens(uint8_t *pass_phase, uint16_t len, uint8_t mode) {
  uint16_t recv_len = 0;
  uint8_t cur_wrflag = 0xff;  // seed and minisecret is different
  cur_wrflag =
      (mode == SE_WRFLG_GENSEED) ? SE_WRFLG_GENSEED : SE_WRFLG_GENMINISECRET;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_SESSION, 0x02, pass_phase, len, NULL,
                             &recv_len, MI2C_ENCRYPT, cur_wrflag)) {
    return false;
  }
  return true;
}

bool se_sessionClose(uint8_t *session_id_bytes) {
  uint16_t recv_len = 0;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_SESSION, 0x02, session_id_bytes, 32,
                             NULL, &recv_len, MI2C_ENCRYPT, GET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool se_set_public_region(const uint16_t offset, const void *val_dest,
                          uint16_t len) {
  uint8_t cmd[5] = {0x00, 0xE6, 0x00, 0x00, 0x10};
  uint8_t recv_buf[8];
  uint16_t recv_len = sizeof(recv_buf);
  if (offset > PUBLIC_REGION_SIZE) return false;
  cmd[2] = (uint8_t)((uint16_t)offset >> 8 & 0x00FF);
  cmd[3] = (uint8_t)((uint16_t)offset & 0x00FF);
  cmd[4] = len;
  memcpy(SH_CMDHEAD, cmd, 5);
  memcpy(SH_IOBUFFER, (uint8_t *)val_dest, len);
  if (MI2C_OK != se_transmit_plain(cmd, 5 + len, recv_buf, &recv_len)) {
    return false;
  }
  return true;
}

bool se_get_public_region(uint16_t offset, void *val_dest, uint16_t len) {
  uint8_t cmd[5] = {0x00, 0xE5, 0x00, 0x00, 0x10};
  uint16_t recv_len = len;
  if (offset > PUBLIC_REGION_SIZE) return false;
  cmd[2] = (uint8_t)((uint16_t)offset >> 8 & 0x00FF);
  cmd[3] = (uint8_t)((uint16_t)offset & 0x00FF);
  cmd[4] = len;
  if (MI2C_OK !=
      se_transmit_plain(cmd, sizeof(cmd), (uint8_t *)val_dest, &recv_len)) {
    return false;
  }

  return true;
}

bool se_set_private_region(uint16_t offset, const void *val_dest,
                           uint16_t len) {
  uint8_t cmd[5] = {0x00, 0xE6, 0x00, 0x00, 0x10};
  uint8_t recv_buf[8];
  uint16_t recv_len = sizeof(recv_buf);
  if (offset + len > PRIVATE_REGION_SIZE) return false;
  offset += SE_PRIVATE_REGION_BASE;
  cmd[2] = (uint8_t)((uint16_t)offset >> 8 & 0x00FF);
  cmd[3] = (uint8_t)((uint16_t)offset & 0x00FF);
  cmd[4] = len;
  memcpy(SH_CMDHEAD, cmd, 5);
  memcpy(SH_IOBUFFER, (uint8_t *)val_dest, len);
  if (MI2C_OK != se_transmit_plain(SH_CMDHEAD, 5 + len, recv_buf, &recv_len)) {
    return false;
  }
  return true;
}

bool se_get_private_region(uint16_t offset, void *val_dest, uint16_t len) {
  uint8_t cmd[5] = {0x00, 0xE5, 0x00, 0x00, 0x10};
  uint16_t recv_len = len;
  if (offset + len > PRIVATE_REGION_SIZE) return false;
  offset += SE_PRIVATE_REGION_BASE;
  cmd[2] = (uint8_t)((uint16_t)offset >> 8 & 0x00FF);
  cmd[3] = (uint8_t)((uint16_t)offset & 0x00FF);
  cmd[4] = len;
  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), val_dest, &recv_len)) {
    return false;
  }
  return true;
}

bool se_get_entroy(uint8_t entroy[32]) {
  if (!randomBuf_SE(entroy, 0x10)) return false;
  if (!randomBuf_SE(entroy + 0x10, 0x10)) return false;
  return true;
}
