#ifndef __SE_CHIP_H__
#define __SE_CHIP_H__

#include <stdbool.h>
#include <stdint.h>

#define IN
#define OUT

#define SESSION_KEYLEN (16)
#define DEFAULT_SECKEYADDR (0x0800F000UL)

// session key addr
#define SESSION_FALG (0x55AA55AA)

//
#define SESSION_FALG_INDEX (0x80)
#define SESSION_ADDR_INDEX (0x81)

#define LITTLE_REVERSE32(w, x)                                       \
  {                                                                  \
    uint32_t tmp = (w);                                              \
    tmp = (tmp >> 16) | (tmp << 16);                                 \
    (x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
  }

#define MI2C_OK 0xAAAAAAAAU
#define MI2C_ERROR 0x00000000U

#define MI2C_ENCRYPT 0x00
#define MI2C_PLAIN 0x80

#define GET_SESTORE_DATA (0x00)
#define SET_SESTORE_DATA (0x01)
#define DELETE_SESTORE_DATA (0x02)
#define DEVICEINIT_DATA (0x03)

#define CURVE_NIST256P1 (0x40)

#define MI2C_CMD_WR_PIN (0xE1)
#define MI2C_CMD_AES (0xE2)
#define MI2C_CMD_ECC_EDDSA (0xE3)
#define MI2C_CMD_READ_SESTOR_REGION (0xE5)
#define MI2C_CMD_WRITE_SESTOR_REGION (0xE6)
#define MI2C_CMD_WR_SESSION (0xE7)

#define PUBLIC_REGION_SIZE (0x600)   // 1.5KB
#define PRIVATE_REGION_SIZE (0x200)  // 0.5KB
#define SE_PRIVATE_REGION_BASE PUBLIC_REGION_SIZE

// ecc ed2519 index
#define ECC_INDEX_GITPUBKEY (0x00)
#define ECC_INDEX_SIGN (0x01)
#define ECC_INDEX_VERIFY (0x02)
#define EDDSA_INDEX_GITPUBKEY (0x03)
#define EDDSA_INDEX_SIGN (0x04)
#define EDDSA_INDEX_VERIFY (0x05)
#define EDDSA_INDEX_CHILDKEY (0x06)
#define EDDSA_INDEX_U2FKEY (0x07)

#define SIGN_NIST256P1 (0x00)
#define SIGN_SECP256K1 (0x01)
#define SIGN_ED25519_DONNA (0x02)
#define SIGN_SR25519 (0x03)
#define SIGN_ED25519_SLIP10 (0x04)

#define SE_EXPORT_SEED (0x24)
#define SE_WRFLG_GENSEED 0                        // se generate seed
#define SE_WRFLG_GENMINISECRET 1                  // se generate minisecret
#define SE_VERIFYPIN_FIRST 0xff                   // for first verify se pin
#define SE_VERIFYPIN_OTHER 0x5a                   // for others
#define SE_GENSEDMNISEC_FIRST SE_VERIFYPIN_FIRST  // for first generate
#define SE_GENSEDMNISEC_OTHER SE_VERIFYPIN_OTHER  // for others

// mnemonic index
#define MNEMONIC_INDEX_TOSEED (26)

#define SE_CMD_GET_VERSION (0xE1)

extern uint8_t g_ucSessionKey[SESSION_KEYLEN];

#if !EMULATOR

extern void se_sync_session_key(void);
extern uint32_t se_transmit(uint8_t ucCmd, uint8_t ucIndex,
                            uint8_t *pucSendData, uint16_t usSendLen,
                            uint8_t *pucRevData, uint16_t *pusRevLen,
                            uint8_t ucMode, uint8_t ucWRFlag);
extern uint32_t se_transmit_plain(uint8_t *pucSendData, uint16_t usSendLen,
                                  uint8_t *pucRevData, uint16_t *pusRevLen);

bool se_device_init(uint8_t mode, const char *passphrase);
bool se_ecdsa_get_pubkey(uint32_t *address, uint8_t count, uint8_t *pubkey);
bool se_set_value(uint16_t key, const void *val_dest, uint16_t len);
bool se_get_value(uint16_t key, void *val_dest, uint16_t max_len,
                  uint16_t *len);
bool se_delete_key(uint16_t key);
void se_reset_storage(void);
bool se_get_sn(char **serial);
char *se_get_version(void);
bool se_verify(void *message, uint16_t message_len, uint16_t max_len,
               void *cert_val, uint16_t *cert_len, void *signature_val,
               uint16_t *signature_len);
bool se_isInitialized(void);
bool se_hasPin(void);
bool se_setPin(uint32_t pin);
bool se_verifyPin(uint32_t pin, uint8_t mode);
bool se_changePin(uint32_t oldpin, uint32_t newpin);
uint32_t se_pinFailedCounter(void);
bool se_isFactoryMode(void);
bool se_isLifecyComSta(void);
bool se_set_u2f_counter(uint32_t u2fcounter);
bool se_get_u2f_counter(uint32_t *u2fcounter);
bool se_setSeed(uint8_t *preCnts, uint8_t mode);
bool se_set_mnemonic(const void *mnemonic, uint16_t len);
bool se_sessionStart(OUT uint8_t *session_id_bytes);
bool se_sessionOpen(IN uint8_t *session_id_bytes);
bool se_sessionGens(uint8_t *pass_phase, uint16_t len, uint8_t mode);
bool se_sessionClose(void);
bool se_get_entroy(uint8_t entroy[32]);
bool se_set_public_region(uint16_t offset, const void *val_dest, uint16_t len);
bool se_get_public_region(uint16_t offset, void *val_dest, uint16_t len);
bool se_set_private_region(uint16_t offset, const void *val_dest, uint16_t len);
bool se_get_private_region(uint16_t offset, void *val_dest, uint16_t len);

#else
#define se_transmit(...) 0
#define se_get_sn(...) false
#define se_get_version(...) "1.1.0.0"
#define se_restore(...) false
#define se_verify(...) false
#define se_set_value(...) false
#define st_restore_entory_from_se(...) false
#define se_reset_storage(...)
#define se_isInitialized(...) false
#define se_hasPin(...) false
#define se_setPin(...) false
#define se_verifyPin(...) false
#define se_changePin(...) false
#define se_pinFailedCounter(...) 0
#define se_importSeed(...) false
#define se_isFactoryMode(...) false
#define se_set_u2f_counter(...) false
#define se_get_u2f_counter(...) false
#define se_set_public_region(...) false
#define se_get_public_region(...) false
#define se_set_private_region(...) false
#define se_get_private_region(...) false
#endif
#endif
