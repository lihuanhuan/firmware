/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libopencm3/stm32/flash.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "bip32.h"
#include "ble.h"
#include "common.h"
#include "config.h"
#include "font.h"
#include "memzero.h"
#include "mi2c.h"
#include "rand.h"
#include "se_chip.h"
#include "secbool.h"
#include "usb.h"
#include "util.h"

#define CONFIG_FIELD(TYPE, NAME) \
  uint8_t has_##NAME;            \
  TYPE NAME

#define CONFIG_BOOL(NAME) CONFIG_FIELD(bool, NAME)
#define CONFIG_STRING(NAME, SIZE) char NAME[SIZE + 1]
#define CONFIG_BYTES(NAME, SIZE) \
  struct {                       \
    uint32_t size;               \
    uint8_t bytes[SIZE];         \
  } NAME
#define CONFIG_UINT32(NAME) CONFIG_FIELD(uint32_t, NAME)
#define CONFIG_UINT64(NAME) CONFIG_FIELD(uint64_t, NAME)

typedef enum {
  LANG_EN_US,
  LANG_ZH_CN,
} LANG_TYPE;

// a helper type to group all public config
typedef struct {
  CONFIG_UINT32(version);
  CONFIG_BYTES(uuid, 12);
  CONFIG_UINT32(language);
  CONFIG_STRING(label, 12);
  CONFIG_BOOL(passphrase_protection);
  CONFIG_BYTES(homescreen, 1024);
  CONFIG_UINT32(auto_lock_delay_ms);
  CONFIG_BOOL(initialized);
  CONFIG_BYTES(session_key, 16);
  CONFIG_BOOL(mnemonics_imported);
  CONFIG_BOOL(sleep_delay_ms);
  CONFIG_UINT32(coin_function_switch);
} PubConfig __attribute__((aligned(1)));

// a helper type to group all private config
typedef struct {
  CONFIG_BOOL(need_backup);
  CONFIG_BOOL(unfinished_backup);
  CONFIG_BOOL(no_backup);
  CONFIG_BOOL(imported);
  CONFIG_BOOL(free_paypin_flag);
  CONFIG_BOOL(free_pay_confirm_flag);
  CONFIG_UINT32(flags);
  CONFIG_UINT32(free_pay_times);
  CONFIG_UINT64(free_pay_limit);
  CONFIG_UINT32(seed_passphrase);

} PriConfig __attribute__((aligned(1)));

// config object store information in SE
struct CfgRecord {
  union {
    uint32_t id;  // use ((access < 16) | offset) as id
    struct {
      uint16_t offset;
      uint16_t access;
    } meta;
  };
  uint32_t size;
};

// Use uint32 as key. lower word for element offset, high word for element flags
// flags: 31 bit for public or private
// should we check `KEY` value ?
#define MARK_PUBLIC_ID(ID) (0 | ID)
#define MARK_PRIVATE_ID(ID) ((1 << 31) | ID)

#define field_size(TYPE, field) sizeof(((TYPE *)0)->field)

#define DEF_PUBLIC_ID(field)                                                 \
  static const struct CfgRecord id_##field = {                               \
      MARK_PUBLIC_ID(offsetof(PubConfig, field)),                            \
      field_size(PubConfig, field),                                          \
  };                                                                         \
  _Static_assert(offsetof(PubConfig, field) + field_size(PubConfig, field) < \
                     PUBLIC_REGION_SIZE,                                     \
                 #field " overflow public region")

#define DEF_PRIVATE_ID(field)                                                \
  static const struct CfgRecord id_##field = {                               \
      MARK_PUBLIC_ID(offsetof(PriConfig, field)),                            \
      field_size(PriConfig, field),                                          \
  };                                                                         \
  _Static_assert(offsetof(PriConfig, field) + field_size(PriConfig, field) < \
                     PRIVATE_REGION_SIZE,                                    \
                 #field " overflow private region")

/// public config elements
// config version
DEF_PUBLIC_ID(version);
// device/config uuid
DEF_PUBLIC_ID(uuid);
// deivce ui language
DEF_PUBLIC_ID(language);
// device label
DEF_PUBLIC_ID(label);
// protected by passphrase
DEF_PUBLIC_ID(passphrase_protection);
// device homescreen
DEF_PUBLIC_ID(homescreen);
// device auto lock delay by ms ///// shutdown
DEF_PUBLIC_ID(auto_lock_delay_ms);
// device has initialized
DEF_PUBLIC_ID(initialized);
// does mnemonic has imported
DEF_PUBLIC_ID(mnemonics_imported);
// device auto lock screen delay by ms
DEF_PUBLIC_ID(sleep_delay_ms);
// switch coin function, ETH SOLANA
DEF_PUBLIC_ID(coin_function_switch);

/// private config elements
// does device need backup?
DEF_PRIVATE_ID(need_backup);
// device has finish backup
DEF_PRIVATE_ID(unfinished_backup);
DEF_PRIVATE_ID(no_backup);
DEF_PRIVATE_ID(imported);
DEF_PRIVATE_ID(free_paypin_flag);
DEF_PRIVATE_ID(free_pay_confirm_flag);
DEF_PRIVATE_ID(flags);
DEF_PRIVATE_ID(free_pay_times);
/* DEF_PRIVATE_ID(free_pay_limit); */
DEF_PRIVATE_ID(seed_passphrase);

#define MAX_SESSIONS_COUNT 10

static secbool se_unlocked = secfalse;

static uint32_t config_uuid[UUID_SIZE / sizeof(uint32_t)];
_Static_assert(sizeof(config_uuid) == UUID_SIZE, "config_uuid has wrong size");

static char config_language[MAX_LANGUAGE_LEN];
_Static_assert(sizeof(config_language) == MAX_LANGUAGE_LEN,
               "config_language has wrong size");

char config_uuid_str[2 * UUID_SIZE + 1] = {0};

/* Current u2f offset, i.e. u2f counter is
 * storage.u2f_counter + config_u2f_offset.
 * This corresponds to the number of cleared bits in the U2FAREA.
 */

// Session management
typedef struct {
  uint8_t id[32];
  uint32_t last_use;
  uint8_t seed[64];
  secbool seedCached;
} Session;

static void session_clearCache(Session *session);
static uint8_t session_findLeastRecent(void);
static uint8_t session_findSession(const uint8_t *sessionId);

static CONFIDENTIAL Session sessionsCache[MAX_SESSIONS_COUNT];
static Session *activeSessionCache;

static uint32_t sessionUseCounter = 0;

#if !EMULATOR
#define autoLockDelayMsDefault (30 * 60 * 1000U)  // 30 minutes
#else
#define autoLockDelayMsDefault (10 * 60 * 1000U)  // 10 minutes
#endif
#define sleepDelayMsDefault (5 * 60 * 1000U)  // 5 minutes

static secbool autoLockDelayMsCached = secfalse;
static secbool sleepDelayMsCached = secfalse;
static uint32_t autoLockDelayMs = autoLockDelayMsDefault;
static uint32_t autoSleepDelayMs = sleepDelayMsDefault;

static SafetyCheckLevel safetyCheckLevel = SafetyCheckLevel_Strict;

static const uint32_t CONFIG_VERSION = 11;

static const uint8_t FALSE_BYTE = '\x00';
static const uint8_t TRUE_BYTE = '\x01';

static uint32_t pin_to_int(const char *pin) {
  uint32_t val = 1;
  size_t i = 0;
  for (i = 0; i < MAX_PIN_LEN && pin[i] != '\0'; ++i) {
    if (pin[i] < '0' || pin[i] > '9') {
      return 0;
    }
    val = 10 * val + pin[i] - '0';
  }

  if (pin[i] != '\0') {
    return 0;
  }

  return val;
}

#define CHECK_CONFIG_OP(cond)     \
  do {                            \
    if (!(cond)) return secfalse; \
  } while (0)

inline static secbool config_get(const struct CfgRecord rcd, void *v) {
  bool pri = rcd.id & (1 << 31);
  bool (*reader)(uint16_t, void *, uint16_t) =
      pri ? se_get_private_region : se_get_public_region;

  uint8_t has;
  // read has_xxx flag
  CHECK_CONFIG_OP(reader(rcd.meta.offset - 1, &has, 1));
  if (has != TRUE_BYTE) return secfalse;

  return reader(rcd.meta.offset, v, rcd.size);
}

inline static secbool config_set(const struct CfgRecord rcd, const void *v,
                                 uint16_t l) {
  bool pri = rcd.id & (1 << 31);
  bool (*writer)(uint16_t, const void *, uint16_t) =
      pri ? se_set_private_region : se_set_public_region;
  // set has_xxx flag
  CHECK_CONFIG_OP(writer(rcd.meta.offset - 1, &TRUE_BYTE, 1));
  return writer(rcd.meta.offset, v, l);
}

inline static secbool config_get_bool(const struct CfgRecord id, bool *value) {
  uint8_t v;
  *value = false;
  CHECK_CONFIG_OP(config_get(id, &v));
  *value = v == TRUE_BYTE;
  return sectrue;
}

inline static secbool config_set_bool(const struct CfgRecord id, bool value) {
  return config_set(id, value ? &TRUE_BYTE : &FALSE_BYTE, 1);
}

inline static secbool config_get_bytes(const struct CfgRecord id, uint8_t *dest,
                                       uint16_t *real_size) {
  bool pri = id.id & (1 << 31);
  bool (*reader)(uint16_t, void *, uint16_t) =
      pri ? se_get_private_region : se_get_public_region;
  uint8_t has;
  // read has_xxx flag
  CHECK_CONFIG_OP(reader(id.meta.offset - 1, &has, 1));
  if (has != TRUE_BYTE) return secfalse;
  uint32_t size = 0;
  // size|bytes
  CHECK_CONFIG_OP(reader(id.meta.offset, &size, sizeof(size)));
  CHECK_CONFIG_OP(reader(id.meta.offset + sizeof(uint32_t), dest, size));
  if (real_size) *real_size = size;
  return sectrue;
}

inline static secbool config_set_bytes(const struct CfgRecord id,
                                       const uint8_t *bytes, uint16_t len) {
  if (len > id.size) return secfalse;

  bool pri = id.id & (1 << 31);
  bool (*writer)(uint16_t, const void *, uint16_t) =
      pri ? se_set_private_region : se_set_public_region;
  // set has_xxx flag
  CHECK_CONFIG_OP(writer(id.meta.offset - 1, &TRUE_BYTE, 1));
  uint32_t size = len;
  // size|bytes
  CHECK_CONFIG_OP(writer(id.meta.offset, &size, sizeof(size)));
  CHECK_CONFIG_OP(writer(id.meta.offset + sizeof(uint32_t), bytes, len));
  return sectrue;
}

inline static secbool config_clear_bytes(const struct CfgRecord id) {
  bool pri = id.id & (1 << 31);
  bool (*writer)(uint16_t, const void *, uint16_t) =
      pri ? se_set_private_region : se_set_public_region;
  // clear has_xxx flag
  CHECK_CONFIG_OP(writer(id.meta.offset - 1, &FALSE_BYTE, 1));
  uint8_t zero[id.size];
  memzero(zero, id.size);
  return writer(id.meta.offset, zero, id.size);
}

inline static secbool config_get_string(const struct CfgRecord id, char *dest,
                                        uint16_t *real_size) {
  if (real_size) *real_size = id.size;
  return config_get(id, dest);
}
inline static secbool config_set_string(const struct CfgRecord id,
                                        const char *dest) {
  uint16_t len = strlen(dest);
  if (len > id.size - 1) return secfalse;
  return config_set(id, dest, len + 1);  // append '\0'
}

#define config_clear_string(id) config_clear_bytes(id)

inline static secbool config_get_uint32(const struct CfgRecord id,
                                        uint32_t *value) {
  *value = 0;
  CHECK_CONFIG_OP(config_get(id, value));
  return sectrue;
}
inline static secbool config_set_uint32(const struct CfgRecord id,
                                        uint32_t value) {
  return config_set(id, &value, sizeof(value));
}

void config_init(void) {
  char oldTiny = usbTiny(1);

  memzero(HW_ENTROPY_DATA, sizeof(HW_ENTROPY_DATA));

  // TODO: check config_init
  config_getLanguage(config_language, sizeof(config_language));

  // imported xprv is not supported anymore so we set initialized to false
  // if no mnemonic is present
  if (config_isInitialized()) {
    config_set_bool(id_initialized, true);
  }

#if !EMULATOR
  // se_sync_session_key();
#endif

  // If UUID is not set, then the config is uninitialized.
  if (sectrue != config_get_bytes(id_uuid, (uint8_t *)config_uuid, NULL)) {
    random_buffer((uint8_t *)config_uuid, sizeof(config_uuid));
    config_set_bytes(id_uuid, (uint8_t *)config_uuid, sizeof(config_uuid));
    config_set_uint32(id_version, CONFIG_VERSION);
  }
  data2hex((const uint8_t *)config_uuid, sizeof(config_uuid), config_uuid_str);

  session_clear(false);

  usbTiny(oldTiny);
}

void session_clear(bool lock) {
  for (uint8_t i = 0; i < MAX_SESSIONS_COUNT; i++) {
    session_clearCache(sessionsCache + i);
  }
  activeSessionCache = NULL;
  if (lock) {
    config_lockDevice();
  }
}

void session_clearCache(Session *session) {
  session->last_use = 0;
  memzero(session->id, sizeof(session->id));
  memzero(session->seed, sizeof(session->seed));
  session->seedCached = false;
}

void config_lockDevice(void) { se_unlocked = secfalse; }

/* static void get_u2froot_callback(uint32_t iter, uint32_t total) { */
/*   layoutProgressAdapter(_("Updating"), 1000 * iter / total); */
/* } */

/* static void config_compute_u2froot(const char *mnemonic, */
/*                                    StorageHDNode *u2froot) { */
/*   static CONFIDENTIAL HDNode node; */
/*   static CONFIDENTIAL uint8_t seed[64]; */
/*   char oldTiny = usbTiny(1); */
/*   mnemonic_to_seed(mnemonic, "", seed, */
/*                    get_u2froot_callback);  // BIP-0039 */
/*   usbTiny(oldTiny); */
/*   hdnode_from_seed(seed, 64, NIST256P1_NAME, &node); */
/*   hdnode_private_ckd(&node, U2F_KEY_PATH); */
/*   u2froot->depth = node.depth; */
/*   u2froot->child_num = U2F_KEY_PATH; */
/*   u2froot->chain_code.size = sizeof(node.chain_code); */
/*   memcpy(u2froot->chain_code.bytes, node.chain_code,
 * sizeof(node.chain_code)); */
/*   u2froot->has_private_key = true; */
/*   u2froot->private_key.size = sizeof(node.private_key); */
/*   memcpy(u2froot->private_key.bytes, node.private_key, */
/*          sizeof(node.private_key)); */
/*   memzero(&node, sizeof(node)); */
/*   memzero(&seed, sizeof(seed)); */
/*   session_clear(false);  // invalidate seed cache */
/* } */

#if DEBUG_LINK

bool config_dumpNode(HDNodeType *node) {
  memzero(node, sizeof(HDNodeType));

  StorageHDNode storageNode = {0};
  uint16_t len = 0;
  if (sectrue !=
          storage_get(KEY_NODE, &storageNode, sizeof(storageNode), &len) ||
      len != sizeof(StorageHDNode)) {
    memzero(&storageNode, sizeof(storageNode));
    return false;
  }

  node->depth = storageNode.depth;
  node->fingerprint = storageNode.fingerprint;
  node->child_num = storageNode.child_num;

  node->chain_code.size = 32;
  memcpy(node->chain_code.bytes, storageNode.chain_code.bytes, 32);

  if (storageNode.has_private_key) {
    node->has_private_key = true;
    node->private_key.size = 32;
    memcpy(node->private_key.bytes, storageNode.private_key.bytes, 32);
  }

  memzero(&storageNode, sizeof(storageNode));
  return true;
}

void config_loadDevice(const LoadDevice *msg) {
  session_clear(false);
  config_set_bool(KEY_IMPORTED, true);
  config_setPassphraseProtection(msg->has_passphrase_protection &&
                                 msg->passphrase_protection);

  if (msg->has_pin) {
    config_changePin("", msg->pin);
  }

  if (msg->mnemonics_count) {
    storage_delete(KEY_NODE);
    config_setMnemonic(msg->mnemonics[0], true);
  }

  if (msg->has_language) {
    config_setLanguage(msg->language);
  }

  config_setLabel(msg->has_label ? msg->label : "");

  if (msg->has_u2f_counter) {
    config_setU2FCounter(msg->u2f_counter);
  }

  if (msg->has_needs_backup) {
    config_setNeedsBackup(msg->needs_backup);
  }

  if (msg->has_no_backup && msg->no_backup) {
    config_setNoBackup();
  }
}

#endif

void config_loadDevice_ex(const BixinLoadDevice *msg) {
  session_clear(false);
  config_set_bool(id_mnemonics_imported, true);

  config_setMnemonic(msg->mnemonics, true);
  config_set_bool(id_initialized, true);

  if (msg->has_language) {
    config_setLanguage(msg->language);
  }

  config_setLabel(msg->has_label ? msg->label : "");
}

void config_setLabel(const char *label) {
  if (label == NULL || label[0] == '\0') {
    config_clear_string(id_label);
  } else {
    config_set_string(id_label, label);
  }
}

void config_setLanguage(const char *lang) {
  if (lang == NULL) {
    return;
  }
  // Sanity check.
  if (strcmp(lang, "en-US") == 0 || strcmp(lang, "english") == 0) {
    ui_language = LANG_EN_US;
  } else if (strcmp(lang, "zh-CN") == 0 || strcmp(lang, "chinese") == 0) {
    ui_language = LANG_ZH_CN;
  } else {
    return;
  }

  config_set_uint32(id_language, ui_language);
  font_set(ui_language ? "dingmao_9x9" : "english");
}

void config_setPassphraseProtection(bool passphrase_protection) {
  config_set_bool(id_passphrase_protection, passphrase_protection);
}

bool config_getPassphraseProtection(bool *passphrase_protection) {
  return config_get_bool(id_passphrase_protection, passphrase_protection);
}

void config_setHomescreen(const uint8_t *data, uint32_t size) {
  if (data != NULL && size == HOMESCREEN_SIZE) {
    config_set_bytes(id_homescreen, data, size);
  } else {
    config_clear_bytes(id_homescreen);
  }
}

/* static bool config_loadNode(const StorageHDNode *node, const char *curve, */
/*                             HDNode *out) { */
/*   return hdnode_from_xprv(node->depth, node->child_num,
 * node->chain_code.bytes, */
/*                           node->private_key.bytes, curve, out); */
/* } */

// 存储在SE里，不支持导出
/* bool config_getU2FRoot(HDNode *node) { */
/*   StorageHDNode u2fNode = {0}; */
/*   uint16_t len = 0; */
/*   if (sectrue != storage_get(KEY_U2F_ROOT, &u2fNode, sizeof(u2fNode), &len)
 * || */
/*       len != sizeof(StorageHDNode)) { */
/*     memzero(&u2fNode, sizeof(u2fNode)); */
/*     return false; */
/*   } */
/*   bool ret = config_loadNode(&u2fNode, NIST256P1_NAME, node); */
/*   memzero(&u2fNode, sizeof(u2fNode)); */
/*   return ret; */
/* } */

bool config_getRootNode(HDNode *node, const char *curve) {
  // TODO change logic, use SE sign
  (void)node;
  (void)curve;

  return true;
}

bool config_getLabel(char *dest, uint16_t dest_size) {
  if (secfalse == config_get_string(id_label, dest, &dest_size)) {
    memcpy(dest, "OneKey Classic", 15 /*strlen("OneKey Classic") + 1*/);
  } else {
    int len = strlen(dest);
    if (0 == len) {
      memcpy(dest, "OneKey Classic", 15);
    }
  }
  return true;
}

bool config_getLanguage(char *dest, uint16_t dest_size) {
  (void)dest_size;
  uint32_t lang_id;
  if (sectrue == config_get_uint32(id_language, &lang_id)) {
    ui_language = lang_id;
  } else {
    ui_language = LANG_EN_US;
  }
  strcpy(dest, ui_language == LANG_ZH_CN ? "zh-CN" : "en-US");
  font_set(ui_language ? "dingmao_9x9" : "english");
  return true;
}

bool config_getHomescreen(uint8_t *dest, uint16_t dest_size) {
  if (id_homescreen.size != dest_size) return secfalse;
  return config_get_bytes(id_homescreen, dest, NULL);
}

bool config_setMnemonic(const char *mnemonic, bool import) {
  if (mnemonic == NULL) {
    return false;
  }
  (void)import;
  if (!se_set_mnemonic((void *)mnemonic, strnlen(mnemonic, MAX_MNEMONIC_LEN))) {
    return false;
  }
  config_set_bool(id_initialized, true);
  return true;
}

bool config_setSeedsBytes(const uint8_t *seeds, uint8_t len) {
  if (seeds == NULL) {
    return false;
  }
  (void)len;

  // TODO:  use SE api set seed
  config_set_bool(id_initialized, true);

  return true;
}

/* Check whether pin matches storage.  The pin must be
 * a null-terminated string with at most 9 characters.
 */
bool config_unlock(const char *pin) {
  if (se_verifyPin((pin_to_int(pin)), SE_VERIFYPIN_OTHER)) {
    se_unlocked = sectrue;
    return true;
  } else {
    se_unlocked = secfalse;
    return false;
  }
}

bool config_hasPin(void) { return se_hasPin(); }

bool config_changePin(const char *old_pin, const char *new_pin) {
  uint32_t new_pin_int = pin_to_int(new_pin);
  if (new_pin_int == 0) {
    return false;
  }
  if (se_changePin(pin_to_int(old_pin), new_pin_int)) {
    se_unlocked = sectrue;
    return true;
  } else {
    se_unlocked = secfalse;
    return false;
  }
}

#if DEBUG_LINK
bool config_getPin(char *dest, uint16_t dest_size) {
  return sectrue == config_get_string(KEY_DEBUG_LINK_PIN, dest, dest_size);
}
#endif

uint8_t session_findLeastRecent(void) {
  uint8_t least_recent_index = MAX_SESSIONS_COUNT;
  uint32_t least_recent_use = sessionUseCounter;
  for (uint8_t i = 0; i < MAX_SESSIONS_COUNT; i++) {
    if (sessionsCache[i].last_use == 0) {
      return i;
    }
    if (sessionsCache[i].last_use <= least_recent_use) {
      least_recent_use = sessionsCache[i].last_use;
      least_recent_index = i;
    }
  }
  ensure(sectrue * (least_recent_index < MAX_SESSIONS_COUNT), NULL);
  return least_recent_index;
}

uint8_t session_findSession(const uint8_t *sessionId) {
  for (uint8_t i = 0; i < MAX_SESSIONS_COUNT; i++) {
    if (sessionsCache[i].last_use != 0) {
      if (memcmp(sessionsCache[i].id, sessionId, 32) == 0) {  // session found
        return i;
      }
    }
  }
  return MAX_SESSIONS_COUNT;
}

uint8_t *session_startSession(const uint8_t *received_session_id) {
  int session_index = MAX_SESSIONS_COUNT;

  if (received_session_id != NULL) {
    session_index = session_findSession(received_session_id);
  }

  if (session_index == MAX_SESSIONS_COUNT) {
    // Session not found in cache. Use an empty one or the least recently
    // used.
    session_index = session_findLeastRecent();
    session_clearCache(sessionsCache + session_index);
    random_buffer(sessionsCache[session_index].id, 32);
  }

  sessionUseCounter++;
  sessionsCache[session_index].last_use = sessionUseCounter;
  activeSessionCache = sessionsCache + session_index;
  return activeSessionCache->id;
}

void session_endCurrentSession(void) {
  if (activeSessionCache == NULL) return;
  session_clearCache(activeSessionCache);
  activeSessionCache = NULL;
}

bool session_isUnlocked(void) {
  if (se_hasPin()) {
    return sectrue == se_unlocked;
  } else {
    return true;
  }
}

bool config_isInitialized(void) {
  bool initialized = false;
  initialized = se_isInitialized();
  return initialized;
}

bool config_getImported(bool *imported) {
  return config_get_bool(id_imported, imported);
}

void config_setImported(bool imported) {
  config_set_bool(id_imported, imported);
}

bool config_getMnemonicsImported(void) {
  bool mnemonic_imported = false;
  config_get_bool(id_mnemonics_imported, &mnemonic_imported);

  return mnemonic_imported;
}

bool config_getNeedsBackup(bool *needs_backup) {
  return sectrue == config_get_bool(id_need_backup, needs_backup);
}

void config_setNeedsBackup(bool needs_backup) {
  config_set_bool(id_need_backup, needs_backup);
}

bool config_getUnfinishedBackup(bool *unfinished_backup) {
  return sectrue == config_get_bool(id_unfinished_backup, unfinished_backup);
}

void config_setUnfinishedBackup(bool unfinished_backup) {
  config_set_bool(id_unfinished_backup, unfinished_backup);
}

bool config_getNoBackup(bool *no_backup) {
  return sectrue == config_get_bool(id_no_backup, no_backup);
}

void config_setNoBackup(void) { config_set_bool(id_no_backup, true); }

void config_applyFlags(uint32_t flags) {
  uint32_t old_flags = 0;
  config_get_uint32(id_flags, &old_flags);
  flags |= old_flags;
  if (flags == old_flags) {
    return;  // no new flags
  }
  config_set_uint32(id_flags, flags);
}

bool config_getFlags(uint32_t *flags) {
  return sectrue == config_get_uint32(id_flags, flags);
}

uint32_t config_nextU2FCounter(void) {
  uint32_t u2fcounter = 0;
  se_get_u2f_counter(&u2fcounter);
  return u2fcounter;
}

void config_setU2FCounter(uint32_t u2fcounter) {
  se_set_u2f_counter(u2fcounter);
}

uint32_t config_getAutoLockDelayMs(void) {
  if (sectrue == autoLockDelayMsCached) {
    return autoLockDelayMs;
  }
#if EMULATOR
  if (sectrue != storage_is_unlocked()) {
    return autoLockDelayMsDefault;
  }
#endif
  if (sectrue != config_get_uint32(id_auto_lock_delay_ms, &autoLockDelayMs)) {
    autoLockDelayMs = autoLockDelayMsDefault;
  }
  if (autoLockDelayMs) {
    autoLockDelayMs = MAX(autoLockDelayMs, MIN_AUTOLOCK_DELAY_MS);
  }
  autoLockDelayMsCached = sectrue;
  return autoLockDelayMs;
}

void config_setAutoLockDelayMs(uint32_t auto_lock_delay_ms) {
  if (auto_lock_delay_ms != 0)
    auto_lock_delay_ms = MAX(auto_lock_delay_ms, MIN_AUTOLOCK_DELAY_MS);
  if (sectrue == config_set_uint32(id_auto_lock_delay_ms, auto_lock_delay_ms)) {
    autoLockDelayMs = auto_lock_delay_ms;
    autoLockDelayMsCached = sectrue;
  }
}

SafetyCheckLevel config_getSafetyCheckLevel(void) { return safetyCheckLevel; }

void config_setSafetyCheckLevel(SafetyCheckLevel safety_check_level) {
  safetyCheckLevel = safety_check_level;
}

uint32_t config_getSleepDelayMs(void) {
  if (sectrue == sleepDelayMsCached) {
    return autoSleepDelayMs;
  }

  if (sectrue != config_get_uint32(id_sleep_delay_ms, &autoSleepDelayMs)) {
    autoSleepDelayMs = sleepDelayMsDefault;
  }
  sleepDelayMsCached = sectrue;
  return autoSleepDelayMs;
}

void config_setSleepDelayMs(uint32_t auto_sleep_ms) {
  if (auto_sleep_ms != 0)
    auto_sleep_ms = MAX(auto_sleep_ms, MIN_AUTOLOCK_DELAY_MS);
  if (sectrue == config_get_uint32(id_sleep_delay_ms, &auto_sleep_ms)) {
    autoSleepDelayMs = auto_sleep_ms;
    sleepDelayMsCached = sectrue;
  }
}

void config_wipe(void) {
  /* uint8_t session_key[16] = {0}; */
  se_reset_storage();
  // TODO: change logic
  // config_getSeSessionKey(session_key, sizeof(session_key));
  se_unlocked = secfalse;
  char oldTiny = usbTiny(1);
  usbTiny(oldTiny);
  random_buffer((uint8_t *)config_uuid, sizeof(config_uuid));
  data2hex((const uint8_t *)config_uuid, sizeof(config_uuid), config_uuid_str);
  autoLockDelayMsCached = secfalse;
  safetyCheckLevel = SafetyCheckLevel_Strict;
  config_set_bytes(id_uuid, (uint8_t *)config_uuid, sizeof(config_uuid));
  config_set_uint32(id_version, CONFIG_VERSION);
  /* config_setSeSessionKey(session_key, 16); */
  config_getLanguage(config_language, sizeof(config_language));

  change_ble_sta(BLE_ADV_ON);
}

void config_setFastPayPinFlag(bool flag) {
  config_set_bool(id_free_paypin_flag, flag);
}

bool config_getFastPayPinFlag(void) {
  bool flag = false;
  config_get_bool(id_free_paypin_flag, &flag);
  return flag;
}

void config_setFastPayConfirmFlag(bool flag) {
  config_set_bool(id_free_pay_confirm_flag, flag);
}
bool config_getFastPayConfirmFlag(void) {
  bool flag = false;
  config_get_bool(id_free_pay_confirm_flag, &flag);
  return flag;
}

void config_setFastPayMoneyLimt(uint64_t MoneyLimt) { (void)MoneyLimt; }

uint64_t config_getFastPayMoneyLimt(void) { return 0; }

void config_setFastPayTimes(uint32_t times) {
  config_set_uint32(id_free_pay_times, times);
}

uint32_t config_getFastPayTimes(void) {
  uint32_t times = 0;
  config_get_uint32(id_free_pay_times, &times);
  return times;
}

void config_setBleTrans(bool mode) {
  ble_set_switch(mode);
  change_ble_sta(mode);
}

void config_setWhetherUseSE(bool flag) {
  (void)flag;
  return;
}

bool config_getWhetherUseSE(void) { return true; }

ExportType config_setSeedsExportFlag(ExportType flag) { return flag; }

bool config_getMessageSE(BixinMessageSE_inputmessage_t *input_msg,
                         BixinOutMessageSE_outmessage_t *get_msg) {
  if (false == bMI2CDRV_SendData(input_msg->bytes, input_msg->size)) {
    return false;
  }
  get_msg->size = 1024;
  if (false == bMI2CDRV_ReceiveData(get_msg->bytes, &get_msg->size)) {
    return false;
  }
  get_msg->bytes[get_msg->size] = '\0';
  return true;
}

void config_setIsBixinAPP(void) { g_bIsBixinAPP = true; }

bool config_setSeedPin(const char *pin) {
  uint32_t seedpin;
  seedpin = pin_to_int(pin);
  if (0x00 == seedpin) {
    return false;
  }
  return config_set_uint32(id_seed_passphrase, seedpin);
}

uint32_t config_getPinFails(void) {
  uint32_t count = 0;
  count = se_pinFailedCounter();
  return count;
}

bool config_getCoinSwitch(CoinSwitch loc) {
  uint32_t coin_switch = 0;
  if (sectrue == config_get_uint32(id_coin_function_switch, &coin_switch)) {
    if (coin_switch & loc) {
      return true;
    }
  }
  return false;
}

void config_setCoinSwitch(CoinSwitch loc, bool flag) {
  uint32_t coin_switch = 0;
  config_get_uint32(id_coin_function_switch, &coin_switch);
  if (flag) {
    coin_switch |= loc;
  } else {
    coin_switch &= ~loc;
  }
  config_set_uint32(id_coin_function_switch, coin_switch);
}
