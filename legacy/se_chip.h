#ifndef __SE_CHIP_H__
#define __SE_CHIP_H__

#include <stdbool.h>
#include <stdint.h>

#define IN
#define OUT

#define SESSION_KEYLEN (16)
#define DEFAULT_SECKEYADDR (0x0800F000UL)

#define PUBLIC_REGION_SIZE (0x600)   // 1.5KB
#define PRIVATE_REGION_SIZE (0x200)  // 0.5KB
#define SE_PRIVATE_REGION_BASE PUBLIC_REGION_SIZE

#define SE_WRFLG_RESET (0x00)                     // se reset on device
#define SE_WRFLG_SETPIN (0x00)                    // se set pin
#define SE_WRFLG_CHGPIN (0x01)                    // se change pin
#define SE_WRFLG_GENSEED (0x00)                   // se generate seed
#define SE_WRFLG_GENMINISECRET (0x01)             // se generate minisecret
#define SE_WRFLG_MNEMONIC SE_WRFLG_GENMINISECRET  // se set mnemonic
#define SE_WRFLG_ENTROPY (0x02)                   // se set entropy
#define SE_VERIFYPIN_FIRST (0xff)                 // for first verify se pin
#define SE_VERIFYPIN_OTHER (0x01)                 // for others
#define SE_GENSEDMNISEC_FIRST SE_VERIFYPIN_FIRST  // for first generate
#define SE_GENSEDMNISEC_OTHER SE_VERIFYPIN_OTHER  // for others
#define SE_GENERATE_SEED_MAX_STEPS 100            // [1, 100] // total 100 steps

bool se_sync_session_key(void);
bool se_device_init(uint8_t mode, const char *passphrase);
bool se_ecdsa_get_pubkey(uint32_t *address, uint8_t count, uint8_t *pubkey);
bool se_set_value(uint16_t key, const void *val_dest, uint16_t len);
bool se_get_value(uint16_t key, void *val_dest, uint16_t max_len,
                  uint16_t *len);
bool se_delete_key(uint16_t key);
void se_reset_storage(void);
bool se_get_sn(char **serial, uint16_t len);
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
bool se_getRetryTimes(uint8_t *ptimes);
bool se_clearSecsta(void);
bool se_setPinValidtime(uint8_t data);
bool se_getPinValidtime(uint8_t *data_buf);
bool se_applyPinValidtime(void);
bool se_getSecsta(void);
bool se_isFactoryMode(void);
bool se_isLifecyComSta(void);
bool se_set_u2f_counter(uint32_t u2fcounter);
bool se_get_u2f_counter(uint32_t *u2fcounter);
bool se_setSeed(uint8_t mode);
bool se_setMinisec(uint8_t mode);
bool se_get_entropy(uint8_t entroy[32]);
bool se_set_entropy(const void *entropy);
bool se_set_mnemonic(const void *mnemonic, uint16_t len);
bool se_sessionStart(OUT uint8_t *session_id_bytes);
bool se_sessionOpen(IN uint8_t *session_id_bytes);
bool se_sessionGens(uint8_t *pass_phase, uint16_t len, uint8_t type,
                    uint8_t mode);
bool se_sessionClose(void);
bool se_sessionClear(void);
bool se_set_public_region(uint16_t offset, const void *val_dest, uint16_t len);
bool se_get_public_region(uint16_t offset, void *val_dest, uint16_t len);
bool se_set_private_region(uint16_t offset, const void *val_dest, uint16_t len);
bool se_get_private_region(uint16_t offset, void *val_dest, uint16_t len);
bool se_schnoor_sign_plain(uint8_t *data, uint16_t data_len, uint8_t *sig,
                           uint16_t max_len, uint16_t *len);
bool se_aes_128_encrypt(uint8_t mode, uint8_t *key, uint8_t *iv, uint8_t *send,
                        uint16_t send_len, uint8_t *recv, uint16_t *recv_len);
bool se_aes_128_decrypt(uint8_t mode, uint8_t *key, uint8_t *iv, uint8_t *send,
                        uint16_t send_len, uint8_t *recv, uint16_t *recv_len);
#endif
