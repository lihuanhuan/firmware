#include "sys/_intsup.h"
#if !defined(EMULATOR) || !EMULATOR
#include "se_chip.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "curves.h"
#include "aes/aes.h"
#include "bip32.h"
#include "mi2c.h"
#include "rand.h"
#include "flash.h"
#include "memzero.h"
#include "hard_preset.h"

#define LITTLE_REVERSE32(w, x)                                       \
  {                                                                  \
    uint32_t ref = (w);                                              \
    ref = (ref >> 16) | (ref << 16);                                 \
    (x) = ((ref & 0xff00ff00UL) >> 8) | ((ref & 0x00ff00ffUL) << 8); \
  }

#define MI2C_OK 0xAAAAAAAAU
#define MI2C_ERROR 0x00000000U

#define MI2C_ENCRYPT 0x00
#define MI2C_PLAIN 0x80

#define GET_SESTORE_DATA (0x00)
#define SET_SESTORE_DATA (0x01)
#define DELETE_SESTORE_DATA (0x02)
#define DEVICEINIT_DATA (0x03)

#define APP (0x01 << 8)

#define SE_INITIALIZED (14 | APP)         // byte
#define SE_PIN (20 | APP)                 // uint32
#define SE_PIN_VALIDTIME (21 | APP)       // byte
#define SE_APPLY_PINVALIDTIME (39 | APP)  // byte
#define SE_VERIFYPIN (22 | APP)           // uint32
#define SE_RESET (27 | APP)
#define SE_SEEDSTRENGTH (30 | APP)    // uint32
#define SE_PIN_RETRYTIMES (37 | APP)  // byte
#define SE_SECSTATUS (38 | APP)       // byte
#define SE_U2FCOUNTER (9 | APP)       // uint32
#define SE_MNEMONIC (2 | APP)         // string(241)
#define SE_ENTROPY SE_MNEMONIC        // bytes(64)
#define SE_PIN_RETRY_MAX 9            // se set pin retry max times

#define MI2C_CMD_WR_PIN (0xE1)
#define MI2C_CMD_AES (0xE2)
#define MI2C_CMD_ECC_EDDSA (0xE3)
#define MI2C_CMD_SCHNOOR (0xE4)
#define MI2C_CMD_READ_SESTOR_REGION (0xE5)
#define MI2C_CMD_WRITE_SESTOR_REGION (0xE6)
#define MI2C_CMD_WR_SESSION (0xE7)
#define MI2C_CMD_WR_MNEMONIC (0xE8)
#define MI2C_CMD_WR_WIPECODE (0xE9)

// ecc ed2519 index
#define ECC_INDEX_GITPUBKEY (0x00)
#define ECC_INDEX_SIGN (0x01)
#define SCHNOOR_INDEX_SIGN ECC_INDEX_SIGN
#define ECC_INDEX_VERIFY (0x02)
#define EDDSA_INDEX_GITPUBKEY (0x03)
#define EDDSA_INDEX_SIGN (0x04)
#define EDDSA_INDEX_VERIFY (0x05)
#define EDDSA_INDEX_CHILDKEY (0x06)
#define EDDSA_INDEX_U2FKEY (0x07)

#define DERIVE_NIST256P1 (0x00)
#define DERIVE_SECP256K1 (0x01)
#define DERIVE_ED25519_DONNA (0x02)
#define DERIVE_SR25519 (0x03)
#define DERIVE_ED25519_SLIP10 (0x04)
// cardano icarus CIP03
// TODO: change to SE required value. now is placeholder
#define DERIVE_ED25519_ICARUS (0x05)
#define DERIVE_ED25519_LEDGER (0x06)

#define CURVE_NIST256P1 (0x40)
#define CURVE_SECP256K1 (0x00)
#define CURVE_ED25519 (0x02)
#define CURVE_SR25519 (0x03)
// cardano icarus CIP03
// TODO: change to SE required value. now is placeholder
#define CURVE_ED25519_ICARUS (0x04)

#define EOS_ECDSA_SIGN (60)
#define ETH_ECDSA_SIGN (194)
#define COM_ECDSA_SIGN (0)
#define SEC_GENK_RFC6979 (0x43)
#define SEC_GENK_RAND (0x65)
#define SEC_GENK_MODE (SEC_GENK_RFC6979)

#define AES_ECB (0x00)
#define AES_CBC (0x01)

uint8_t g_ucSessionKey[SESSION_KEYLEN];

uint32_t se_transmit_plain(uint8_t *pucSendData, uint16_t usSendLen,
                           uint8_t *pucRevData, uint16_t *pusRevLen);

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

static bool xor_cal(uint8_t *pucSrc1, uint8_t *pucSrc2, uint16_t usLen,
                    uint8_t *pucDest) {
  uint16_t i;

  for (i = 0; i < usLen; i++) {
    pucDest[i] = pucSrc1[i] ^ pucSrc2[i];
  }
  return true;
}

/*
 *master i2c synsessionkey
 */
bool se_sync_session_key(void) {
  uint8_t r1[16], r2[16], r3[32];
  uint8_t default_key[16] = {0xff};  // TODO need read
                                     // from special
                                     // flash addr
  memset(default_key, 0xff, 16);
  uint8_t data_buf[64], hash_buf[32];
  uint8_t sync_cmd[5 + 48] = {0x00, 0xfa, 0x00, 0x00, 0x30};
  uint16_t recv_len = 0xff;
  aes_encrypt_ctx en_ctxe;
  aes_decrypt_ctx de_ctxe;
  // TODO
  memzero(data_buf, sizeof(data_buf));
  if (!bPresetDataRead(default_key)) return false;

  // get random from se
  randomBuf_SE(r1, 16);
  // get random itself
  random_buffer_ST(r2, 16);
  // organization data1
  memcpy(r3, r1, sizeof(r1));
  memcpy(r3 + sizeof(r1), r2, sizeof(r2));
  aes_encrypt_key128(default_key, &en_ctxe);
  aes_ecb_encrypt(r3, data_buf, sizeof(r1) + sizeof(r2), &en_ctxe);

  // cal tmp sessionkey with x hash256
  memzero(r3, sizeof(r3));
  xor_cal(r1, r2, sizeof(r1), r3);
  memcpy(r3 + 16, default_key, 16);
  hasher_Raw(HASHER_SHA2, r3, 32, hash_buf);
  // use session key organization data2
  memcpy(g_ucSessionKey, hash_buf, 16);
  aes_encrypt_key128(g_ucSessionKey, &en_ctxe);
  aes_ecb_encrypt(r1, data_buf + 32, sizeof(r1), &en_ctxe);
  // send data1 + data2 to se and recv returned result
  memcpy(sync_cmd + 5, data_buf, 48);
  if (MI2C_OK !=
      se_transmit_plain(sync_cmd, sizeof(sync_cmd), data_buf, &recv_len)) {
    memset(g_ucSessionKey, 0x00, SESSION_KEYLEN);
    return false;
  }

  // handle the returned data
  aes_decrypt_key128(g_ucSessionKey, &de_ctxe);
  aes_ecb_decrypt(data_buf, r3, recv_len, &de_ctxe);
  if (memcmp(r2, r3, sizeof(r2)) != 0) {
    memset(g_ucSessionKey, 0x00, SESSION_KEYLEN);
    return false;
  }

  return true;
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
    if ((SET_SESTORE_DATA & ucWRFlag) || (DEVICEINIT_DATA & ucWRFlag) ||
        (SE_WRFLG_SETPIN == ucWRFlag) ||
        (SE_WRFLG_CHGPIN == ucWRFlag)) {  // TODO. pin process
      // data aes encrypt
      randomBuf_SE(ucRandom, sizeof(ucRandom));
      memset(&ctxe, 0, sizeof(aes_encrypt_ctx));
      aes_encrypt_key128(g_ucSessionKey, &ctxe);
      memcpy(SH_IOBUFFER, ucRandom, sizeof(ucRandom));
      memcpy(SH_IOBUFFER + sizeof(ucRandom), pucSendData, usSendLen);
      usSendLen += sizeof(ucRandom);
      // add pad
      // if (usSendLen % AES_BLOCK_SIZE) {
      // }
      usPadLen = AES_BLOCK_SIZE - (usSendLen % AES_BLOCK_SIZE);
      memset(SH_IOBUFFER + usSendLen, 0x00, usPadLen);
      SH_IOBUFFER[usSendLen] = 0x80;
      usSendLen += usPadLen;
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
    // TODO. add le
    if (MI2C_CMD_ECC_EDDSA == ucCmd) {
      SH_CMDHEAD[usSendLen] = 0x00;
      SH_CMDHEAD[usSendLen + 1] = 0x00;
      usSendLen += 2;
    }
  } else {
    P3 = usSendLen & 0xFF;
    if (MI2C_ENCRYPT == ucMode) {
      memcpy(SH_IOBUFFER, g_ucMI2cRevBuf, usSendLen);
    } else {
      memcpy(SH_IOBUFFER, pucSendData, usSendLen);
    }
    usSendLen += 5;
    // TODO add le
    if (MI2C_CMD_ECC_EDDSA == ucCmd) {
      SH_CMDHEAD[usSendLen] = 0x00;
      usSendLen += 1;
    }
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
      // TODO
      memzero(SH_IOBUFFER, g_usMI2cRevLen);
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

inline static uint32_t se_transmit_ex(uint8_t ucCmd, uint8_t ucIndex,
                                      uint8_t *pucSendData, uint16_t usSendLen,
                                      uint8_t *pucRevData, uint16_t *pusRevLen,
                                      uint8_t ucMode, uint8_t ucWRFlag,
                                      bool bFirst) {
  uint8_t ucRandom[16], i;
  uint16_t usPadLen;
  aes_encrypt_ctx ctxe;
  aes_decrypt_ctx ctxd;
  // se apdu
  if (MI2C_ENCRYPT == ucMode) {  // TODO. set seed and minisecret process
    if ((SET_SESTORE_DATA & ucWRFlag) || (DEVICEINIT_DATA & ucWRFlag) ||
        (SE_WRFLG_GENSEED == ucWRFlag) ||
        (SE_WRFLG_GENMINISECRET == ucWRFlag)) {
      // data aes encrypt
      randomBuf_SE(ucRandom, sizeof(ucRandom));
      memset(&ctxe, 0, sizeof(aes_encrypt_ctx));
      aes_encrypt_key128(g_ucSessionKey, &ctxe);
      memcpy(SH_IOBUFFER, ucRandom, sizeof(ucRandom));
      memcpy(SH_IOBUFFER + sizeof(ucRandom), pucSendData, usSendLen);
      usSendLen += sizeof(ucRandom);
      // add pad
      // if ((usSendLen % AES_BLOCK_SIZE) || (usSendLen / AES_BLOCK_SIZE)) {
      // }
      usPadLen = AES_BLOCK_SIZE - (usSendLen % AES_BLOCK_SIZE);
      memset(SH_IOBUFFER + usSendLen, 0x00, usPadLen);
      SH_IOBUFFER[usSendLen] = 0x80;
      usSendLen += usPadLen;
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
    CLA = 0x90;
  else
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

bool se_get_result_plain(uint8_t *pRecv, uint16_t *pRecv_len) {
  uint16_t recv_len = 0xff;
  if (false == bMI2CDRV_ReceiveData(pRecv, &recv_len)) {
    *pRecv_len = recv_len;
    return false;
  }
  *pRecv_len = 0xff;
  return true;
}

inline static bool se_get_resp_by_ecdsa256(uint8_t mode,
                                           const uint32_t *address,
                                           uint8_t count, uint8_t *resp,
                                           uint16_t *resp_len) {
  if (MI2C_OK != se_transmit(MI2C_CMD_ECC_EDDSA, EDDSA_INDEX_CHILDKEY,
                             (uint8_t *)address, count * 4, resp, resp_len,
                             MI2C_PLAIN, mode)) {
    return false;
  }

  return true;
}

inline static bool se_get_derive_mode_by_name(const char *curve,
                                              uint8_t *mode) {
  if (0 == strcmp(curve, NIST256P1_NAME)) {
    *mode = DERIVE_NIST256P1;
  } else if (0 == strcmp(curve, SECP256K1_NAME)) {
    *mode = DERIVE_SECP256K1;
  } else if (0 == strcmp(curve, ED25519_NAME)) {
    *mode = DERIVE_ED25519_SLIP10;
  } else if (0 == strcmp(curve, SR25519_NAME)) {
    *mode = DERIVE_SR25519;
  } else if (0 == strcmp(curve, ED25519_CARDANO_NAME)) {
    *mode = DERIVE_ED25519_ICARUS;
  } else if (0 == strcmp(curve, ED25519_LEDGER_NAME)) {
    *mode = DERIVE_ED25519_LEDGER;
    //
    // } else if (0 == strcmp(curve, ED25519_KECCAK_NAME)) {
    //   *mode = DERIVE_ED25519_DONNA;
  } else {
    return false;
  }

  return true;
}

// TODO se_get_hnode_public
bool se_derive_keys(HDNode *out, const char *curve, const uint32_t *address_n,
                    size_t address_n_count, uint32_t *fingerprint) {
  uint8_t resp[256];
  uint16_t resp_len;
  uint8_t mode;

  if (!se_get_derive_mode_by_name(curve, &mode)) return false;

  if (MI2C_OK != se_transmit(MI2C_CMD_ECC_EDDSA, EDDSA_INDEX_CHILDKEY,
                             (uint8_t *)address_n, address_n_count * 4, resp,
                             &resp_len, MI2C_PLAIN, mode)) {
    return false;
  }

  switch (mode) {
    case DERIVE_NIST256P1:
    case DERIVE_SECP256K1:
      out->depth = resp[0];
      out->child_num = *(uint32_t *)(resp + 1);
      out->curve = get_curve_by_name(curve);
      memcpy(out->chain_code, resp + 1 + 4, 32);
      HDNode parent = {0};
      parent.curve = get_curve_by_name(curve);
      memcpy(parent.public_key, resp + 1 + 4 + 32, 33);
      if (fingerprint) {
        *fingerprint = hdnode_fingerprint(&parent);
      }
      memcpy(out->public_key, resp + 1 + 4 + 32 + 33, 33);
      break;
    case DERIVE_ED25519_SLIP10:
      out->curve = get_curve_by_name(curve);
      if (33 != resp_len) return false;
      if (fingerprint) fingerprint = NULL;
      memcpy(out->public_key, resp, resp_len);
      // keep same `hdnode_fill_public_key` in bip32.c
      out->public_key[0] = 1;
      break;
    default:
      return false;
  }

  return true;
}

inline static bool se_get_pubkey_by_25519(uint8_t mode, uint8_t *chain_code,
                                          uint16_t chain_len, uint8_t *pubkey) {
  uint8_t resp[256];
  uint16_t resp_len;

  if ((mode != DERIVE_ED25519_DONNA) && (mode != DERIVE_SR25519)) return false;
  if ((chain_code[0] != 0) && (chain_code[0] != 1)) return false;
  if (0 != chain_len % 33) return false;

  if (MI2C_OK != se_transmit(MI2C_CMD_ECC_EDDSA, EDDSA_INDEX_CHILDKEY,
                             chain_code, chain_len, resp, &resp_len, MI2C_PLAIN,
                             mode)) {
    return false;
  }
  memcpy(pubkey, resp, 32);
  return true;
}

// TODO it will add function in bip32.c
bool se_get_hnode_public_by_polkadot_path(HDNode *out, const char *curve,
                                          const char (*address_n)[130],
                                          size_t address_n_count) {
  uint8_t mode = DERIVE_SR25519;

  if (NULL == out || NULL == curve) {
    return false;
  }

  if (0 == strcmp(curve, SR25519_NAME)) {
    mode = DERIVE_SR25519;
  } else if (0 == strcmp(curve, ED25519_NAME)) {
    mode = DERIVE_ED25519_DONNA;
  } else {
    return false;
  }

  out->curve = get_curve_by_name(curve);
  if (NULL == out->curve) {
    return false;
  }

  if (!address_n
      // no way how to compute parent fingerprint
      || 0 == address_n_count) {
    return false;
  }

  uint8_t chaincode_list[330];
  memset(chaincode_list, 0x00, sizeof(chaincode_list) / sizeof(uint8_t));
  size_t chaincode_list_len = 0;
  // bool bSuccess = true;
  // for (size_t k = 0; k < address_n_count; ++k) {
  //   // for (size_t k = 1; k < address_n_count; ++k) {
  //   HDNode cc = *out;
  //   if (0 == hdnode_chaincode_ckd_by_polkadot_path(&cc, address_n[k])) {
  //     bSuccess = false;
  //     break;
  //   }
  //   memcpy(&chaincode_list[k * (sizeof(cc.public_key) / sizeof(uint8_t))],
  //          cc.public_key, sizeof(cc.public_key) / sizeof(uint8_t));
  //   chaincode_list_len += sizeof(cc.public_key) / sizeof(uint8_t);
  // }
  // if (!bSuccess) {
  //   return bSuccess;
  // }

  return se_get_pubkey_by_25519(mode, chaincode_list, chaincode_list_len,
                                &out->public_key[1]);
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

bool se_set_spec_value(uint16_t key, const void *val_dest, uint16_t len,
                       uint8_t wr_flg) {
  uint8_t flag = key >> 8;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (key & 0xFF), (uint8_t *)val_dest,
                             len, NULL, 0, (flag & MI2C_PLAIN), wr_flg)) {
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
              MI2C_ENCRYPT, SE_WRFLG_RESET);
}

bool se_get_sn(char **serial, uint16_t len) {
  uint8_t ucSnCmd[5] = {0x00, 0xf5, 0x01, 0x00, 0x0a};
  static char sn[32] = {0};
  uint16_t sn_len = sizeof(sn);

  if (len > 0x0a) len = 0x0a;
  ucSnCmd[4] = len;
  // TODO
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
      // TODO. se sn change 10
      if (se_get_sn(&se_sn, 0x0a)) {
        if (strcmp(se_sn, "Bixin2304") > 0) {
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

bool se_isInitialized(void) {
  if (se_isLifecyComSta()) {
    return true;
  }
  return false;
}

bool se_hasPin(void) { return se_isInitialized(); }

bool se_verifyPin(uint32_t pin, uint8_t mode) {
  uint8_t retry = 0;
  uint16_t len = sizeof(retry);

  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (SE_VERIFYPIN & 0xFF),
                             (uint8_t *)&pin, sizeof(pin), &retry, &len,
                             MI2C_ENCRYPT, mode)) {
    return false;
  }

  return true;
}

bool se_setPin(uint32_t pin) {
  uint16_t recv_len = 0xff;

  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (SE_PIN & 0xFF), (uint8_t *)&pin,
                             sizeof(pin), NULL, &recv_len, MI2C_ENCRYPT,
                             SE_WRFLG_SETPIN)) {
    return false;
  }
  return true;
}

bool se_changePin(uint32_t oldpin, uint32_t newpin) {
  uint8_t pin_buff[10];
  uint16_t recv_len = 0xff;

  pin_buff[0] = 4;
  memcpy(pin_buff + 1, (uint8_t *)&oldpin, sizeof(uint32_t));
  pin_buff[5] = 4;
  memcpy(pin_buff + 6, (uint8_t *)&newpin, sizeof(uint32_t));

  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (SE_PIN & 0xFF),
                             (uint8_t *)&pin_buff, sizeof(pin_buff), NULL,
                             &recv_len, MI2C_ENCRYPT, SE_WRFLG_CHGPIN)) {
    return false;
  }
  return true;
}

bool se_getRetryTimes(uint8_t *pcnts) {
  uint8_t cmd[5 + 16] = {0x80, 0xe1, 0x25, 0x00, 0x10};
  uint8_t recv_buf[0x20], ref_buf[0x20], rand_buf[0x10];
  uint16_t recv_len = 0xff;  // 32 bytes session id
  aes_decrypt_ctx aes_dec_ctx;

  // TODO. get se random 16 bytes
  random_buffer_ST(rand_buf, 0x10);
  memcpy(cmd + 5, rand_buf, sizeof(rand_buf));
  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), recv_buf, &recv_len)) {
    return false;
  }
  // TODO. parse returned data
  if (recv_len != 0x20) return false;
  aes_decrypt_key128(g_ucSessionKey, &aes_dec_ctx);
  aes_ecb_decrypt(recv_buf, ref_buf, recv_len, &aes_dec_ctx);
  if (memcmp(ref_buf, rand_buf, sizeof(rand_buf)) != 0) return false;

  // TODO: retry cnts
  if (ref_buf[0x10] > SE_PIN_RETRY_MAX) return false;
  *pcnts = ref_buf[0x10];
  return true;
}

uint32_t se_pinFailedCounter(void) {
  uint8_t retry_cnts = 0;
  if (!se_getRetryTimes(&retry_cnts)) {
    return 0;
  }

  return (uint32_t)(SE_PIN_RETRY_MAX - retry_cnts);
}

bool se_clearSecsta(void) {
  uint8_t cmd[5] = {0x80, 0xe1, 0x26, 0x01, 0x00};
  uint16_t recv_len = 0xff;

  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), NULL, &recv_len)) {
    return false;
  }
  return true;
}

bool se_getSecsta(void) {
  uint8_t cmd[5] = {0x80, 0xe1, 0x26, 0x00, 0x00};
  uint8_t cur_secsta = 0xff;
  uint16_t recv_len = 0xff;

  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), &cur_secsta, &recv_len)) {
    return false;
  }
  // 0x55 is verified pin 0x00 is not verified pin
  return cur_secsta == 0x55;
}

bool se_setPinValidtime(uint8_t data) {
  uint16_t recv_len = 0xff;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (SE_PIN_VALIDTIME & 0xFF), &data,
                             1, NULL, &recv_len, MI2C_ENCRYPT,
                             SET_SESTORE_DATA)) {
    return false;
  }

  return true;
}

bool se_getPinValidtime(uint8_t *data_buf) {
  uint8_t cmd[5 + 16] = {0x80, 0xe1, 0x15, 0x00, 0x10};
  uint8_t recv_buf[0x20], ref_buf[0x20], rand_buf[0x10];
  uint16_t recv_len = 0xff;  // 32 bytes session id
  aes_decrypt_ctx aes_dec_ctx;

  // TODO. get se random 16 bytes
  random_buffer_ST(rand_buf, 0x10);
  memcpy(cmd + 5, rand_buf, sizeof(rand_buf));
  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), recv_buf, &recv_len)) {
    return false;
  }
  // TODO. parse returned data
  if (recv_len != 0x20) return false;
  aes_decrypt_key128(g_ucSessionKey, &aes_dec_ctx);
  aes_ecb_decrypt(recv_buf, ref_buf, recv_len, &aes_dec_ctx);
  if (memcmp(ref_buf, rand_buf, sizeof(rand_buf)) != 0) return false;

  // TODO. setted valid time and remained valid time
  memcpy(data_buf, ref_buf + sizeof(rand_buf), 3);
  return true;
}

bool se_applyPinValidtime(void) {
  uint16_t recv_len = 0xff;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_PIN, (SE_APPLY_PINVALIDTIME & 0xFF),
                             NULL, 0, NULL, &recv_len, MI2C_ENCRYPT,
                             GET_SESTORE_DATA)) {
    return false;
  }

  return true;
}

// first used it will return false and retry counter
// last will return true
// note : first used mode = SE_GENSEDMNISEC_FIRST
//        other mode =SE_GENSEDMNISEC_OTHER
// bool se_setSeed(uint8_t *preCnts, uint8_t mode) {
bool se_setSeed(uint8_t mode) {
  uint8_t cmd[5] = {0x80, 0xe1, 0x12, 0x00, 0x00};
  uint8_t cur_cnts = 0xff;
  uint16_t recv_len = 0;

  // TODO
  if (SE_GENSEDMNISEC_FIRST != mode && SE_GENSEDMNISEC_OTHER != mode)
    return false;
  if (SE_GENSEDMNISEC_FIRST == mode) {
    if (MI2C_OK != se_transmit_ex(MI2C_CMD_WR_PIN, 0x12, NULL, 0, &cur_cnts,
                                  &recv_len, MI2C_ENCRYPT, SE_WRFLG_GENSEED,
                                  mode)) {
      return false;
    }
  } else {
    if (false == se_transmit_plain(cmd, sizeof(cmd), &cur_cnts, &recv_len)) {
      return false;
    }
  }

  return true;
}

// bool se_setMinisec(uint8_t *preCnts, uint8_t mode) {
bool se_setMinisec(uint8_t mode) {
  uint8_t cmd[5] = {0x80, 0xe1, 0x12, 0x01, 0x00};
  uint8_t recv_buf[4];
  uint16_t recv_len = 0;
  // TODO
  if (SE_GENSEDMNISEC_FIRST != mode && SE_GENSEDMNISEC_OTHER != mode)
    return false;
  if (SE_GENSEDMNISEC_FIRST == mode) {
    if (MI2C_OK != se_transmit_ex(MI2C_CMD_WR_PIN, 0x12, NULL, 0, recv_buf,
                                  &recv_len, MI2C_ENCRYPT,
                                  SE_WRFLG_GENMINISECRET, mode)) {
      return false;
    }
  } else {
    if (false == se_transmit_plain(cmd, sizeof(cmd), recv_buf, &recv_len)) {
      return false;
    }
  }

  return true;
}

se_generate_state_t se_beginGenerate(se_generate_type_t type,
                                     se_generate_session_t *session) {
  uint8_t cur_cnts = 0xff;
  uint16_t recv_len = 0;
  if (MI2C_OK == se_transmit_ex(MI2C_CMD_WR_PIN, 0x12, NULL, 0, &cur_cnts,
                                &recv_len, MI2C_ENCRYPT, type, PROCESS_BEGIN)) {
    return STATE_FAILD;
  }
  session->processing = PROCESS_GENERATING;
  session->type = type;
  return STATE_GENERATING;
}

se_generate_state_t se_generating(se_generate_session_t *session) {
  uint8_t cmd[5] = {0x80, 0xe1, 0x12, 0x00, 0x00};
  uint8_t cur_cnts = 0xff;
  uint16_t recv_len = 0;
  cmd[3] = session->type;
  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), &cur_cnts, &recv_len)) {
    return STATE_GENERATING;
  }

  return STATE_COMPLETE;
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
  return se_set_spec_value(SE_MNEMONIC, mnemonic, len, SE_WRFLG_MNEMONIC);
}

bool se_get_entropy(uint8_t entropy[32]) {
  if (!randomBuf_SE(entropy, 0x10)) return false;
  if (!randomBuf_SE(entropy + 0x10, 0x10)) return false;
  return true;
}

bool se_set_entropy(const void *entropy, uint16_t len) {
  return se_set_spec_value(SE_ENTROPY, entropy, len, SE_WRFLG_ENTROPY);
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

bool se_sessionStart(OUT uint8_t *session_id_bytes) {
  uint8_t cmd[5] = {0x80, 0xe7, 0x00, 0x00, 0x00};
  uint8_t recv_buf[0x20];
  uint16_t recv_len = 0xff;  // 32 bytes session id

  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), recv_buf, &recv_len)) {
    return false;
  }
  // TODO. parse returned data
  memcpy(session_id_bytes, recv_buf, 0x20);
  return true;
}

bool se_sessionOpen(IN uint8_t *session_id_bytes) {
  uint16_t recv_len = 0;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_SESSION, 0x01, session_id_bytes, 32,
                             NULL, &recv_len, MI2C_ENCRYPT, GET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

// TODO. type is seed or minisecret
bool se_sessionGens(uint8_t *pass_phase, uint16_t len, uint8_t type,
                    uint8_t mode) {
  uint8_t cmd[5] = {0x80, 0xe7, 0x02, 0x00, 0x00};
  uint8_t cur_cnts = 0xff;
  uint8_t cur_wrflag = 0xff;  // seed and minisecret is different
  cur_wrflag =
      (type == SE_WRFLG_GENSEED) ? SE_WRFLG_GENSEED : SE_WRFLG_GENMINISECRET;
  uint16_t recv_len = 0;

  // TODO
  if (SE_GENSEDMNISEC_FIRST != mode && SE_GENSEDMNISEC_OTHER != mode)
    return false;
  if (SE_GENSEDMNISEC_FIRST == mode) {
    if (pass_phase == NULL) {  // TODO. it would use default seed and
                               // minisecret.
      return MI2C_OK == se_transmit_ex(MI2C_CMD_WR_SESSION, 0x02, NULL, 0,
                                       &cur_cnts, &recv_len, MI2C_ENCRYPT,
                                       cur_wrflag, mode);
    }
    if (MI2C_OK != se_transmit_ex(MI2C_CMD_WR_SESSION, 0x02, pass_phase, len,
                                  &cur_cnts, &recv_len, MI2C_ENCRYPT,
                                  cur_wrflag, mode)) {
      return false;
    }
  } else {
    if (type == SE_WRFLG_GENMINISECRET) cmd[3] = 0x01;
    if (false == se_transmit_plain(cmd, sizeof(cmd), &cur_cnts, &recv_len)) {
      return false;
    }
  }

  return true;
}

se_generate_state_t se_sessionBeginGenerate(const uint8_t *passphase,
                                            uint16_t len,
                                            se_generate_type_t type,
                                            se_generate_session_t *session) {
  uint8_t cur_cnts = 0xff;
  uint16_t recv_len = 0;
  unsigned int ret =
      se_transmit_ex(MI2C_CMD_WR_SESSION, 0x02, (uint8_t *)passphase, len,
                     &cur_cnts, &recv_len, MI2C_ENCRYPT, type, PROCESS_BEGIN);
  if (ret == MI2C_OK) {
    return STATE_COMPLETE;
  }
  session->processing = PROCESS_GENERATING;
  session->type = type;
  return STATE_GENERATING;
}

se_generate_state_t se_sessionGenerating(se_generate_session_t *session) {
  uint8_t cmd[5] = {0x80, 0xe7, 0x02, 0x00, 0x00};
  uint8_t cur_cnts = 0xff;
  uint16_t recv_len = 0;
  cmd[3] = session->type;
  if (MI2C_OK != se_transmit_plain(cmd, sizeof(cmd), &cur_cnts, &recv_len)) {
    return STATE_GENERATING;
  }

  return STATE_COMPLETE;
}

bool se_sessionClose(void) {
  uint16_t recv_len = 0;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_SESSION, 0x03, NULL, 0, NULL,
                             &recv_len, MI2C_ENCRYPT, GET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

bool se_sessionClear(void) {
  uint16_t recv_len = 0;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_SESSION, 0x04, NULL, 0, NULL,
                             &recv_len, MI2C_ENCRYPT, GET_SESTORE_DATA)) {
    return false;
  }
  return true;
}

// TODO: lc is three bytes
bool se_set_public_region(const uint16_t offset, const void *val_dest,
                          uint16_t len) {
  uint8_t cmd[7] = {0x00, 0xE6, 0x00, 0x00, 0x00, 0x04, 0x00};
  uint8_t recv_buf[8];
  uint16_t recv_len = sizeof(recv_buf);

  if (offset > PUBLIC_REGION_SIZE) return false;
  cmd[2] = (uint8_t)((uint16_t)offset >> 8 & 0x00FF);
  cmd[3] = (uint8_t)((uint16_t)offset & 0x00FF);
  cmd[4] = 0;
  cmd[5] = len >> 8;
  cmd[6] = len;
  memcpy(SH_CMDHEAD, cmd, 7);
  memcpy(SH_IOBUFFER + 2, (uint8_t *)val_dest, len);
  if (MI2C_OK != se_transmit_plain(SH_CMDHEAD, 7 + len, recv_buf, &recv_len)) {
    return false;
  }
  return true;
}
// TODO: le is three bytes
bool se_get_public_region(uint16_t offset, void *val_dest, uint16_t len) {
  uint8_t cmd[7] = {0x00, 0xE5, 0x00, 0x00, 0x00, 0x00, 0x10};
  uint16_t recv_len = len;
  if (offset > PUBLIC_REGION_SIZE) return false;
  cmd[2] = (uint8_t)((uint16_t)offset >> 8 & 0x00FF);
  cmd[3] = (uint8_t)((uint16_t)offset & 0x00FF);
  cmd[4] = 0;
  cmd[5] = len >> 8;
  cmd[6] = len;
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

bool se_ecdsa_sign_digest(uint8_t curve, const uint8_t *hash, uint8_t *sig,
                          uint8_t *v) {
  uint8_t resp[128], tmp[40];
  uint16_t resp_len = 0x41;
  uint32_t mode = ETH_ECDSA_SIGN;

  memset(tmp, 0x00, sizeof(tmp));
  LITTLE_REVERSE32(mode, mode);
  memcpy(tmp, &mode, sizeof(uint32_t));
  tmp[4] = SEC_GENK_RFC6979;
  memcpy(tmp + 5, hash, 32);  // for special sign add mode (4 bytes)+genk(1
                              // byte)+hash(32 byte),so total len is 37.
  if (MI2C_OK != se_transmit(MI2C_CMD_ECC_EDDSA, ECC_INDEX_SIGN, tmp,
                             (4 + 1 + 32), resp, &resp_len, MI2C_ENCRYPT,
                             curve)) {
    return false;
  }
  memcpy(sig, resp + 1, 64);
  if (v) *v = resp[0];
  return true;
}
#define se_secp256k1_sign_digest(hash, sig, v) \
  se_ecdsa_sign_digest(CURVE_SECP256K1, hash, sig, v)
#define se_nist256p1_sign_digest(hash, sig, v) \
  se_ecdsa_sign_digest(CURVE_NIST256P1, hash, sig, v)

bool se_25519_sign(uint8_t curve, const uint8_t *msg, uint16_t msg_len,
                   uint8_t *sig) {
  uint8_t resp[128];
  uint16_t resp_len;
  if (MI2C_OK != se_transmit(MI2C_CMD_ECC_EDDSA, EDDSA_INDEX_SIGN,
                             (uint8_t *)msg, msg_len, resp, &resp_len,
                             MI2C_ENCRYPT, curve)) {
    return false;
  }
  memcpy(sig, resp, resp_len);
  return true;
}

#define se_ed25519_sign(msg, msg_len, sig) \
  se_25519_sign(CURVE_ED25519, msg, msg_len, sig)

// ed25519 ext sign
#define se_ed25519_icarus_sign(msg, msg_len, sig) \
  se_25519_sign(CURVE_ED25519_ICARUS, msg, msg_len, sig)

#define se_sr25519_sign(msg, msg_len, sig) \
  se_25519_sign(CURVE_SR25519, msg, msg_len, sig)

// TODO it will sign digest
bool se_schnoor_sign_plain(const uint8_t *data, uint16_t data_len,
                           uint8_t *sig) {
  uint8_t resp[128];
  uint16_t resp_len;

  if (MI2C_OK != se_transmit(MI2C_CMD_SCHNOOR, SCHNOOR_INDEX_SIGN,
                             (uint8_t *)data, data_len, resp, &resp_len,
                             MI2C_ENCRYPT, GET_SESTORE_DATA)) {
    return false;
  }
  if (resp_len != 64) {
    return false;
  }
  memcpy(sig, resp, 64);
  return true;
}

bool se_aes_128_encrypt(uint8_t mode, uint8_t *key, uint8_t *iv, uint8_t *send,
                        uint16_t send_len, uint8_t *recv, uint16_t *recv_len) {
  uint8_t cmd[5] = {0x80, 0xE2, 0x01, 0x00, 0x00};
  uint16_t data_len;

  if (AES_ECB != mode && AES_CBC != mode) return false;
  data_len = 0;

  // TODO
  if (AES_CBC == mode) {
    memcpy(SH_IOBUFFER + data_len, iv, 16);
    data_len += 16;
  }
  memcpy(SH_IOBUFFER + data_len, key, 16);
  data_len += 16;
  cmd[3] = mode;  // p2 is work mode
  // TODO
  memcpy(SH_CMDHEAD, cmd, 5);
  memcpy(SH_IOBUFFER, (uint8_t *)send, send_len);
  data_len += send_len;
  if (MI2C_OK != se_transmit_plain(cmd, 5 + data_len, recv, recv_len)) {
    return false;
  }
  return true;
}

bool se_aes_128_decrypt(uint8_t mode, uint8_t *key, uint8_t *iv, uint8_t *send,
                        uint16_t send_len, uint8_t *recv, uint16_t *recv_len) {
  uint8_t cmd[5] = {0x80, 0xE2, 0x00, 0x00, 0x00};
  uint16_t data_len;

  if (AES_ECB != mode && AES_CBC != mode) return false;
  data_len = 0;

  // TODO
  if (AES_CBC == mode) {
    memcpy(SH_IOBUFFER + data_len, iv, 16);
    data_len += 16;
  }
  memcpy(SH_IOBUFFER + data_len, key, 16);
  data_len += 16;
  cmd[3] = mode;  // p2 is work mode
  // TODO
  memcpy(SH_CMDHEAD, cmd, 5);
  memcpy(SH_IOBUFFER, (uint8_t *)send, send_len);
  data_len += send_len;
  if (MI2C_OK != se_transmit_plain(cmd, 5 + data_len, recv, recv_len)) {
    return false;
  }
  return true;
}

/// hdnode api

int hdnode_private_ckd_cached(HDNode *inout, const uint32_t *address_n,
                              size_t address_n_count, uint32_t *fingerprint) {
  // just tell se derive keys, DO NOT cache anything
  se_derive_keys(inout, inout->curve->curve_name, address_n, address_n_count,
                 fingerprint);
  return 1;
}

int hdnode_sign_digest(const HDNode *node, const uint8_t *digest, uint8_t *sig,
                       uint8_t *pby, int (*is_canonical)(uint8_t, uint8_t *)) {
  const char *curve = node->curve->curve_name;
  if (strcmp(curve, SECP256K1_NAME) == 0) {
    if (!se_secp256k1_sign_digest(digest, sig, pby)) return -1;
    if (is_canonical && !is_canonical(*pby, sig)) return -1;
    return 0;
  } else if (strcmp(curve, NIST256P1_NAME) == 0) {
    if (!se_nist256p1_sign_digest(digest, sig, pby)) return -1;
    if (is_canonical && !is_canonical(*pby, sig)) return -1;
    return 0;
  }
  return -1;
}

int hdnode_sign(const HDNode *node, const uint8_t *msg, uint32_t msg_len,
                HasherType hasher_sign, uint8_t *sig, uint8_t *pby,
                int (*is_canonical)(uint8_t, uint8_t *)) {
  if (node->curve->params) {
    uint8_t hash[32] = {0};
    hasher_Raw(hasher_sign, msg, msg_len, hash);
    return hdnode_sign_digest(node, hash, sig, pby, is_canonical);
  } else {
    // 25519 sign
    const char *curve = node->curve->curve_name;
    if (strcmp(curve, ED25519_NAME) == 0) {
      if (!se_ed25519_sign(msg, msg_len, sig)) return -1;
      return 0;
    } else if (strcmp(curve, SR25519_NAME) == 0) {
      if (!se_sr25519_sign(msg, msg_len, sig)) return -1;
      return 0;
    } else if (strcmp(curve, ED25519_CARDANO_NAME) == 0) {
      if (!se_ed25519_icarus_sign(msg, msg_len, sig)) return -1;
      return 0;
    } else if (strcmp(curve, ED25519_LEDGER_NAME) == 0) {
      if (!se_ed25519_sign(msg, msg_len, sig)) return -1;
      return 0;
    }
  }
  return -1;
}

int hdnode_bip340_sign_digest(const HDNode *node, const uint8_t *digest,
                              uint8_t sig[64]) {
  (void)node;
  return se_schnoor_sign_plain(digest, 32, sig) ? 0 : 1;
}

int hdnode_bip340_get_shared_key(const HDNode *node,
                                 const uint8_t *peer_public_key,
                                 uint8_t session_key[65]) {
  (void)node;
  (void)*peer_public_key;
  (void)session_key;

  return 0;
}

bool se_containsMnemonic(const char *mnemonic) {
  uint8_t resp[256];
  uint16_t resp_len;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_MNEMONIC, 0x00, (uint8_t *)mnemonic,
                             strlen(mnemonic), resp, &resp_len, MI2C_ENCRYPT,
                             GET_SESTORE_DATA)) {
    return false;
  }
  if (resp[0] == 0x01) return true;
  return false;
}

bool se_hasWipeCode(void) {
  uint8_t resp[256];
  uint16_t resp_len;
  if (MI2C_OK != se_transmit(MI2C_CMD_WR_WIPECODE, 0x01, NULL, 0, resp,
                             &resp_len, MI2C_ENCRYPT, GET_SESTORE_DATA)) {
    return false;
  }
  if (resp[0] == 0x01) return true;
  return false;
}
bool se_changeWipeCode(uint32_t wipe_code) {
  uint16_t recv_len = 0xff;

  if (MI2C_OK != se_transmit(MI2C_CMD_WR_WIPECODE, 0x00, (uint8_t *)&wipe_code,
                             sizeof(wipe_code), NULL, &recv_len, MI2C_ENCRYPT,
                             SE_WRFLG_SETPIN)) {
    return false;
  }

  return true;
}

uint16_t se_lasterror(void) { return get_lasterror(); }

#endif
