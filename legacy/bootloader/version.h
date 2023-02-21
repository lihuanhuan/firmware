// 每个byte用到0-9，升级：0x1109 -> 0x1110,  格式化： 0x1110 = 1.1.10
#define BOOT_VERSION_HEX 0x1900
// #define VERSION_MAJOR (uint8_t)(BOOT_VERSION_HEX >> 12)
// #define VERSION_MINOR (uint8_t)(BOOT_VERSION_HEX >> 8) & 0x0F
/*
#define VERSION_PATCH                                 \
  (uint8_t)(((BOOT_VERSION_HEX & 0x00FF) >> 4) * 10 + \
            ((BOOT_VERSION_HEX & 0x00FF) & 0x0F))
*/

#define VERSION_MAJOR 1
#define VERSION_MINOR 9
#define VERSION_PATCH 0

#define VERSION_MAJOR_CHAR "\x01"
#define VERSION_MINOR_CHAR "\x09"
#define VERSION_PATCH_CHAR "\x00"
