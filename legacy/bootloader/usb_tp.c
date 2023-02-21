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
#include "usb.h"
#include <mk21/flash.h>
#include <mk21/usb/usb_private.h>
#include <string.h>
#include "aes/aes.h"
#include "bootloader.h"
#include "buttons.h"
#include "ecdsa.h"
#include "layout.h"
#include "layout_boot.h"
#include "memory.h"
#include "memzero.h"
#include "mi2c.h"
#include "rng.h"
#include "secbool.h"
#include "secp256k1.h"
#include "sha2.h"
#include "si2c.h"
#include "signatures.h"
#include "spi.h"
#include "sys.h"
#include "usart.h"
#include "usb21_standard.h"
#include "usb_desc.h"
#include "util.h"
#include "webusb.h"
#include "winusb.h"

#if 0
const uint8_t K21_AESKEY[16] = {0xCF,0xF6,0x6B,0x4A,0x82,0xE4,0x13,0x34,0x77,0x6A,0xA2,0xAC,0xB3,0x89,0x5B,0x87 };
const uint8_t K21_AESIV[16] = {0xFD,0x07,0xd0,0xa5,0x07,0xf8,0x03,0xec,0x80,0x90,0xce,0x7f,0x5e,0x6C,0x81,0x9A};
//将公钥定义到指定地址位置
const uint8_t pubkey_ST[65]  = {
	0x04,0xb2,0x4f,0xce,0x9b,0xbb,0x79,0x8e,0x87,0x58,0x0a,0x43,0xbb,0xdd,0x60,0xbf,0x73,
	0x8a,0x85,0x56,0xe6,0xab,0x83,0xd7,0x60,0xe3,0x50,0x34,0x7e,0x38,0x45,0xca,0x39,
	0x60,0xff,0x73,0x0f,0xe3,0xc8,0xd4,0xdf,0xdf,0xf3,0xc4,0xef,0x06,0xcf,0xb4,0x6f,
	0xb1,0xb8,0x10,0xc1,0x31,0xb5,0x75,0xb3,0x61,0x55,0x80,0x11,0xf6,0xa2,0xec,0xd2
};
const uint8_t pubkey_flash[65] = {	
	0x04,0x3e,0x41,0x6b,0x53,0x92,0x0b,0xed,0x7b,0x72,0xe5,0x95,0x08,0x3a,0xf9,0xad,0x6d,
	0x32,0x00,0x94,0x5d,0xc5,0x7d,0x7e,0xd3,0xc9,0x08,0x9b,0x47,0x0a,0x1f,0xc2,0xd2,
	0x35,0x54,0xa5,0xa1,0x28,0xd5,0x0e,0x6e,0x40,0x09,0xed,0x4f,0x78,0xdf,0xdf,0x62,
	0xcf,0xd9,0x43,0x7d,0x44,0x2c,0x72,0x25,0x76,0x78,0x99,0xb4,0x2f,0xf1,0xa0,0xcc
};
const uint8_t pubkey_BLE[65] = {	
	0x04,0xe9,0x93,0xd1,0xeb,0x1a,0xf0,0x56,0x72,0x96,0x5f,0x55,0xa5,0xd0,0x05,0x0c,0x95,
	0xec,0x86,0x6b,0x3e,0xd1,0xd6,0x84,0x71,0x1f,0xfc,0x38,0xd2,0x4d,0x89,0x13,0x78,
	0x04,0xa3,0xdb,0x2d,0xf0,0xa0,0xb2,0x8e,0x49,0x8a,0x87,0xf5,0x89,0x57,0xbb,0x83,
	0xeb,0x7c,0x53,0xe6,0xdc,0x6a,0x7b,0xe4,0x64,0x2f,0xd7,0x96,0x8e,0x1a,0xb9,0xe8
};

#define pubkey_ST (PubKeysForUpdate)
#define K21_AESKEY (pubkey_ST + 65)
#define K21_AESIV (K21_AESKEY + 16)
#define pubkey_flash (K21_AESIV + 16)
#define pubkey_BLE (pubkey_flash + 65)
#endif

// const uint8_t PubKeysForUpdate[FLASH_PAGE_SIZE]
// __attribute__((at(0x00019000))) = {
const uint8_t PubKeysForUpdate[FLASH_PAGE_SIZE] = {
    // ST 公钥
    0x04, 0xb2, 0x4f, 0xce, 0x9b, 0xbb, 0x79, 0x8e, 0x87, 0x58, 0x0a,
    0x43, 0xbb, 0xdd, 0x60, 0xbf, 0x73, 0x8a, 0x85, 0x56, 0xe6, 0xab,
    0x83, 0xd7, 0x60, 0xe3, 0x50, 0x34, 0x7e, 0x38, 0x45, 0xca, 0x39,
    0x60, 0xff, 0x73, 0x0f, 0xe3, 0xc8, 0xd4, 0xdf, 0xdf, 0xf3, 0xc4,
    0xef, 0x06, 0xcf, 0xb4, 0x6f, 0xb1, 0xb8, 0x10, 0xc1, 0x31, 0xb5,
    0x75, 0xb3, 0x61, 0x55, 0x80, 0x11, 0xf6, 0xa2, 0xec, 0xd2,
};

#define PUBKEY_ST (PubKeysForUpdate)

static SHA256_CTX ctx = {0};
static uint8_t hash[32] = {0};
static char flash_state = STATE_READY;
static uint32_t g_uiExFlashAddr = 0xFFFFFFFF;
static uint32_t g_uiUpPercent = 0;
static uint32_t g_uiUpFileLens = 0;
static uint8_t packet_buf[64] __attribute__((aligned(4)));
uint32_t flash_pos = 0, flash_len = 0;
BOTFLGSTR g_vsBootFlgs;

/*btn status change global static variable*/
static bool btn_left = false;
static bool btn_right = false;
static bool btn_final = false;
static bool ucIsConfirmed = false;
static bool ucIsUpgraded = false;
#include "usb_send.h"

static uint32_t chunk_idx = 0;
uint32_t FW_HEADER[FLASH_FWHEADER_LEN / sizeof(uint32_t)];
static uint32_t FW_CHUNK[FW_CHUNK_SIZE / sizeof(uint32_t)];
static uint8_t update_mode = 0;
static uint8_t version[2] = {0};
static uint8_t BLEAPP_VERSION[2] = {0};
static uint16_t usCerLen;
// static uint8_t ucVersionChecked = 0;
// static void __attribute__((noreturn)) shutdown(void) {
//   // sleep(5);
//   exit(4);
// }

/*Together init static */
void boot_init_static_para(void) {
  flash_state = STATE_READY;
  g_uiExFlashAddr = 0;
  g_uiUpFileLens = 0;
  flash_pos = 0;
  flash_len = 0;
  chunk_idx = 0;
  update_mode = 0;
  btn_left = false;
  btn_right = false;
  btn_final = false;
  update_mode = 0;
#if 0
    ucVersionChecked = 1;
#endif
}

/*Press any key to continue*/
void BootloaderProgContinue(bool is_upgSuccess) {
  while (waitButtonResponse(0, default_oper_time)) {
  };
  if (!is_upgSuccess) {
    sys_bootShutdown();
  } else {
    sys_bootPowerReset();
  }
  return;
}

#include "usb_erase.h"

#if 0
//设置版本号
static uint8_t SetVersion(void)
{
    uint8_t aucBuf[32],usOff,tmpVersion[14],ucFlag;
    uint16_t usLen,usCurVersion,usOldVersion;
    ucFlag = 0;//标志版本号是否有更新
   
    //GetVersion from SE
			aucBuf[0] = 0x80;
			aucBuf[1] = 0xFC;
			aucBuf[2] = 0x00;
			aucBuf[3] = 0x10;
			aucBuf[4] = 0x00;
			usLen = 0xFF;
      if (false == bMI2CDRV_SendData(aucBuf, 5)) {
  			return VERSION_TRANS_ERROR;
	    }
      delay_ms(5);
			memzero(tmpVersion, sizeof(tmpVersion));      	
			if (false == bMI2CDRV_ReceiveData(tmpVersion, &usLen)) {
				return VERSION_TRANS_ERROR;
			}
      for(usOff = 0; usOff < sizeof(version);usOff+=2)
      {
        usCurVersion = PTYP_iBERamWord(version+usOff);
        usOldVersion = PTYP_iBERamWord(tmpVersion+usOff);
        if((usCurVersion != 0xFFFF) && ((usOldVersion == 0xFFFF) || (usCurVersion > usOldVersion)))
        {
          //将新版本号赋值过去
          memcpy(tmpVersion + usOff, version + usOff, 2);    
          ucFlag = 1;      
        }
      }
      //往SE中设置版本号
      if(1 == ucFlag)
      {
        aucBuf[0] = 0x80;
        aucBuf[1] = 0xFC;
        aucBuf[2] = 0x00;
        aucBuf[3] = 0x11;
        aucBuf[4] = sizeof(tmpVersion);
        memcpy(aucBuf + 5,tmpVersion,sizeof(tmpVersion));

        if (false == bMI2CDRV_SendData(aucBuf, 5+sizeof(tmpVersion))) {
          return VERSION_TRANS_ERROR;
        }
        delay_ms(5);
        usLen = 0xFF;
        memzero(aucBuf, sizeof(aucBuf));      	
        if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
          return VERSION_TRANS_ERROR;
        }
      }
      return 0;
}

//检查固件升级版本号
static uint8_t checkVersion(void)
{
    uint8_t aucBuf[32],usOff,ucFlag;
    uint16_t usLen,usCurVersion,usOldVersion;
    
    ucFlag = 0;//强制升级标志初始化
    // check mandatry update flag
    if(((image_header *)FW_HEADER)->fix_version != 0)
    {
      ucFlag = 0x01;//设置为强制升级
    }
    //GetVersion from SE
			aucBuf[0] = 0x80;
			aucBuf[1] = 0xFC;
			aucBuf[2] = 0x00;
			aucBuf[3] = 0x10;
			aucBuf[4] = 0x00;
			usLen = 0xFF;
      if (false == bMI2CDRV_SendData(aucBuf, 5)) {
  			return VERSION_TRANS_ERROR;
	    }
      delay_ms(5);
			memzero(aucBuf, sizeof(aucBuf));      	
			if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
				return VERSION_TRANS_ERROR;
			}

      //get curversion and oldversion(SE 中为大端格式，Header数据中也为大端格式)
      usCurVersion = PTYP_iBERamWord((((uint8_t*)FW_HEADER) + 22));
      
      if(update_mode == UPDATE_ST)
      {
        usOldVersion = PTYP_iBERamWord(aucBuf);    
        usOff = 0;      
      }
      else
      if(update_mode == UPDATE_SE)
      {
        usOldVersion = PTYP_iBERamWord(aucBuf+2);
        usOff = 0x02;
      }
      else
      if(update_mode == UPDATE_FLASH)
      {
        usOldVersion = PTYP_iBERamWord(aucBuf + 4);
        usOff = 0x04;
      }
      else
      if(update_mode == UPDATE_BLE)
      {
        usOldVersion = PTYP_iBERamWord(aucBuf + 6);
        usOff = 0x06;
      }
      if(ucFlag)//强制升级直接设置版本号
      {
              memcpy(aucBuf + usOff, ((uint8_t*)&(FW_HEADER)) + 22, 2);  
              memcpy(aucBuf + 5,aucBuf,sizeof(version));
              aucBuf[0] = 0x80;
              aucBuf[1] = 0xFC;
              aucBuf[2] = 0x00;
              aucBuf[3] = 0x11;
              aucBuf[4] = sizeof(version);
              usLen = 0xFF;
              if (false == bMI2CDRV_SendData(aucBuf, 5+sizeof(version))) {
                return VERSION_TRANS_ERROR;
              }
              delay_ms(5);
              memzero(aucBuf, sizeof(aucBuf));      	
              if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
                return VERSION_TRANS_ERROR;
              }
              return VERSION_NEW;

      }
      //check version
      if((usOldVersion == 0xFFFF) || (usCurVersion > usOldVersion))
      {
        //版本号赋值
        memcpy(version + usOff, ((uint8_t*)&(FW_HEADER)) + 22, 2);
        return VERSION_NEW;
      }
      else
      {
        return VERSION_OLD_ERROR;
      }
}
#endif

//-------------------------------------------------
// name:bBLE_GetBLEAppVersion
// parameter:
//		pucData:存储获取的版本号
// return:
//
// description:
//		从BLE获取2字节版本号
//-------------------------------------------------
bool bBLE_GetBLEAppVersion(uint8_t *pucData) {
  uint8_t aucBuf[32];
  // GetVersion from SE
  aucBuf[0] = 0x80;
  aucBuf[1] = 0xFC;
  aucBuf[2] = 0x00;
  aucBuf[3] = 0x06;
  aucBuf[4] = 0x00;

  ble_usart_send(aucBuf, 5);
  ble_usart_receive(aucBuf, 4);
  if ((aucBuf[2] != 0x90) || (aucBuf[3] != 0x00)) {
    return false;
  }
  memcpy(pucData, aucBuf, 2);
  return TRUE;
}

//-------------------------------------------------
// name:bSE_SetBLEAppVersion
// parameter:
//		pucData:待写入的蓝牙版本号
// return:
//
// description:
//		将BLE版本号写入到SE中
//-------------------------------------------------
bool bSE_SetBLEAppVersion(uint8_t *pucData) {
  uint8_t aucBuf[32];
  uint16_t usLen;
  if ((pucData[0] == pucData[1]) && (0 == pucData[0])) {
    //没有升级蓝牙APP，设置蓝牙版本号直接返回成功
    return true;
  }
  //设置蓝牙版本，在公有区偏移为13开始的2字节
  aucBuf[0] = 0x00;
  aucBuf[1] = 0xE6;
  aucBuf[2] = 0x00;
  aucBuf[3] = 0x0D;
  aucBuf[4] = 0x02;
  aucBuf[5] = pucData[0];
  aucBuf[6] = pucData[1];

  if (false == bMI2CDRV_SendData(aucBuf, 7)) {
    return false;
  }
  delay_ms(50);
  memzero(aucBuf, sizeof(aucBuf));
  usLen = 0xFF;
  if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
    return false;
  }
  return TRUE;
}

//-------------------------------------------------
// name:vSE_GetVersion
// parameter:
//		pucData:存储获取的版本号
// return:
//
// description:
//		从SE获取2字节版本号
//-------------------------------------------------
bool bSE_GetVersion(uint8_t *pucData) {
  uint8_t aucBuf[32];
  uint16_t usLen;
  // GetVersion from SE
  aucBuf[0] = 0x80;
  aucBuf[1] = 0xFC;
  aucBuf[2] = 0x00;
  aucBuf[3] = 0x10;
  aucBuf[4] = 0x00;
  usLen = 0xFF;
  if (false == bMI2CDRV_SendData(aucBuf, 5)) {
    return false;
  }
  delay_ms(5);
  memzero(aucBuf, sizeof(aucBuf));
  if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
    return false;
  }
  memcpy(pucData, aucBuf, 2);
  return TRUE;
}

//-------------------------------------------------
// name:vSE_SetVersion
// parameter:
//		pucData:存储获取的版本号
// return:
//
// description:
//		从SE设置2字节版本号
//-------------------------------------------------
static bool bSE_SetVersion(void) {
  uint8_t aucBuf[32];
  uint16_t usLen;
  memset(aucBuf, 0xFF, sizeof(aucBuf));
  // GetVersion from SE
  aucBuf[0] = 0x80;
  aucBuf[1] = 0xFC;
  aucBuf[2] = 0x00;
  aucBuf[3] = 0x11;
  aucBuf[4] = 0x02;
  aucBuf[5] = version[0];
  aucBuf[6] = version[1];
  usLen = 0xFF;
  if (false == bMI2CDRV_SendData(aucBuf, 7)) {
    return false;
  }
  delay_ms(20);
  memzero(aucBuf, sizeof(aucBuf));
  if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
    return false;
  }
  return TRUE;
}

//-------------------------------------------------
// name:send_msg_cer
// parameter:
//
// return:
//
// description:
//		发送证书数据
//-------------------------------------------------
static void send_msg_cer(usbd_device *dev) {
  uint8_t response[64];
  uint16_t usOff;
  memzero(response, sizeof(response));
  memcpy(response,
         // header
         "?##"
         // msg_id
         "\x00\x0A"
         // msg_size
         "\x00\x00",
         5);
  response[7] = (usCerLen >> 8) & 0xFF;
  response[8] = usCerLen;
  memcpy(response + 9, ((uint8_t *)FW_HEADER), 55);
  send_response(dev, response);
  usOff = 55;
  while (usOff < usCerLen) {
    memzero(response, sizeof(response));
    response[0] = 0x3F;
    if (usCerLen - usOff > 63) {
      memcpy(response + 1, ((uint8_t *)FW_HEADER) + usOff, 63);
      usOff += 63;
    } else {
      memcpy(response + 1, ((uint8_t *)FW_HEADER) + usOff, (usCerLen - usOff));
      usOff = usCerLen;
    }
    send_response(dev, response);
  }
}

//-------------------------------------------------
// name:bSE_GetState
// parameter:
//		ucState:status
// return:
//		TRUE/FALSE
// description:
//		get the status of the SE
//-------------------------------------------------
static bool bSE_GetState(uint8_t *ucState) {
  uint8_t aucBuf[5];
  uint16_t usLen;
  aucBuf[0] = 0x80;
  aucBuf[1] = 0xFC;
  aucBuf[2] = 0x00;
  aucBuf[3] = 0x00;
  aucBuf[4] = 0x00;
  // SE
  if ((UPDATE_SE == update_mode) || (UPDATE_SKEY == update_mode)) {
    if (false == bMI2CDRV_SendData(aucBuf, 5)) {
      return false;
    }
    delay_ms(100);
    usLen = 0xFF;
    if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
      return false;
    }
  } else {  // BLE
    ble_usart_send(aucBuf, 5);
    ble_usart_receive(aucBuf, 3);
    if ((aucBuf[1] != 0x90) || (aucBuf[2] != 0x00)) {
      return false;
    }
    usLen = 1;
  }
  if ((usLen != 0x01) ||
      ((aucBuf[0] != 0x00) && (aucBuf[0] != 0x55) && (aucBuf[0] != 0x33))) {
    return false;
  }
  *ucState = aucBuf[0];
  return true;
}

//-------------------------------------------------
// name:bSE_Back2Boot
// parameter:
//
// return:
//		TRUE/FALSE
// description:
//		set SE to boot state
//-------------------------------------------------
static bool bSE_Back2Boot(void) {
  uint8_t aucBuf[5];
  uint16_t usLen;
  aucBuf[0] = 0x80;
  aucBuf[1] = 0xFC;
  aucBuf[2] = 0x00;
  aucBuf[3] = 0xFF;
  aucBuf[4] = 0x00;
  // if(UPDATE_SE == update_mode)
  if ((UPDATE_SE == update_mode) || (UPDATE_SKEY == update_mode)) {
    if (false == bMI2CDRV_SendData(aucBuf, 5)) {
      return false;
    }
    delay_ms(10);
    usLen = 0xFF;
    if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
      return false;
    }
  } else {  // BLE
    ble_usart_send(aucBuf, 5);
    ble_usart_receive(aucBuf, 2);
    if ((aucBuf[0] != 0x90) || (aucBuf[1] != 0x00)) {
      return false;
    }
  }
  return true;
}

//-------------------------------------------------
// name:bSE_AcitveAPP
// parameter:
//
// return:
//		TRUE/FALSE
// description:
//		set SE APP active
//-------------------------------------------------
static bool bSE_AcitveAPP(void) {
  uint8_t aucBuf[5];
  uint16_t usLen;
  aucBuf[0] = 0x80;
  aucBuf[1] = 0xFC;
  aucBuf[2] = 0x00;
  aucBuf[3] = 0x04;
  aucBuf[4] = 0x00;
  if (UPDATE_SE == update_mode) {
    if (false == bMI2CDRV_SendData(aucBuf, 5)) {
      return false;
    }
    delay_ms(10);
    usLen = 0xFF;
    if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
      return false;
    }
  } else {  // BLE 串口通信
    ble_usart_send(aucBuf, 5);
    ble_usart_receive(aucBuf, 2);
    if ((aucBuf[0] != 0x90) || (aucBuf[1] != 0x00)) {
      return false;
    }
  }
  return true;
}

//-------------------------------------------------
// name:bSE_Update
// parameter:
//		ucStep:01:first step to verify sig;
//			   02:update data;
//			   03:verify hash
// return:
//		TRUE/FALSE
// description:
//		update firmware
//-------------------------------------------------
static bool bSE_Update(uint8_t ucStep) {
  uint8_t aucBuf[519], *pucTmp;
  uint16_t usLen;
  aucBuf[0] = 0x80;
  aucBuf[1] = 0xFC;
  aucBuf[2] = 0x00;
  aucBuf[3] = ucStep;
  aucBuf[4] = 0x00;
  // 发送部分
  if (0x01 == ucStep) {
    aucBuf[4] = 0x60;
    memcpy(aucBuf + 5, &(((image_header *)FW_HEADER)->hashes), 32);
    memcpy(aucBuf + 5 + 32, &(((image_header *)FW_HEADER)->sig1), 64);
    usLen = 101;
    if ((UPDATE_SE == update_mode) || (UPDATE_SKEY == update_mode)) {
      if (false == bMI2CDRV_SendData(aucBuf, usLen)) {
        return false;
      }
      delay_ms(50);
    } else {  // BLE
      ble_usart_send(aucBuf, usLen);
    }
  } else if ((0x02 == ucStep) || (0x05 == ucStep)) {
    aucBuf[5] = 0x02;
    aucBuf[6] = 0x00;
    pucTmp = (uint8_t *)FW_CHUNK +
             ((flash_pos - 512 - FLASH_FWHEADER_LEN) % FW_CHUNK_SIZE);
    memcpy(aucBuf + 7, pucTmp, 512);
    usLen = 519;
    // if(UPDATE_SE == update_mode)
    if ((UPDATE_SE == update_mode) || (UPDATE_SKEY == update_mode)) {
      if (false == bMI2CDRV_SendData(aucBuf, usLen)) {
        return false;
      }
      delay_ms(5);
    } else {  // BLE
      ble_usart_send(aucBuf, usLen);
    }
  } else if (0x03 == ucStep) {
    usLen = 5;
    if ((UPDATE_SE == update_mode) || (UPDATE_SKEY == update_mode)) {
      if (false == bMI2CDRV_SendData(aucBuf, usLen)) {
        return false;
      }
      delay_ms(10);
    } else {  // BLE
      ble_usart_send(aucBuf, usLen);
    }
  }
  // 接收部分
  if ((UPDATE_SE == update_mode) || (UPDATE_SKEY == update_mode)) {
    usLen = 0xFF;
    if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
      return false;
    }
  } else {  // BLE
    ble_usart_receive(aucBuf, 2);
    if ((aucBuf[0] != 0x90) || (aucBuf[1] != 0x00)) {
      return false;
    }
  }
  return true;
}

//-------------------------------------------------
// name:bSE_DevSign
// parameter:
//    pucData:输入HASH值/输出签名结果
// return:
//		TRUE/FALSE
// description:
//		set SE APP active
//-------------------------------------------------
static bool bSE_DevSign(uint8_t *pucData) {
  uint8_t aucBuf[100];
  uint16_t usLen;
  aucBuf[0] = 0x00;
  aucBuf[1] = 0x72;
  aucBuf[2] = 0x00;
  aucBuf[3] = 0x00;
  aucBuf[4] = 0x20;
  memcpy(aucBuf + 5, pucData, 32);
  if (false == bMI2CDRV_SendData(aucBuf, 37)) {
    return false;
  }
  delay_ms(10);
  usLen = 0xFF;
  if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
    return false;
  }
  memcpy(pucData, aucBuf, 64);
  return true;
}

//-------------------------------------------------
// name:bSE_GetCert
// parameter:
//    pucData:返回证书内容
// return:
//		TRUE/FALSE
// description:
//		set SE APP active
//-------------------------------------------------
static bool bSE_GetCert(uint8_t *pucData) {
  uint8_t aucBuf[5];
  uint16_t usLen;
  aucBuf[0] = 0x00;
  aucBuf[1] = 0xF8;
  aucBuf[2] = 0x01;
  aucBuf[3] = 0x00;
  aucBuf[4] = 0x00;
  if (false == bMI2CDRV_SendData(aucBuf, 5)) {
    return false;
  }
  delay_ms(10);
  usLen = 0xFFFF;
  if (false == bMI2CDRV_ReceiveData(pucData, &usLen)) {
    return false;
  }
  usCerLen = usLen;
  // memcpy(pucData,aucBuf,64);
  return true;
}

//读取K21公钥
static void vK21_ReadPubkey(uint8_t *pucKey) {
  uint16_t usLen;
  //检查秘钥区是否存在秘钥
  ucFLASH_Read(K21_KEY_ADDR, pucKey, KEYINFO_LEN);
  for (usLen = 0; usLen < KEYINFO_LEN; usLen++) {
    if (*(pucKey + usLen) != 0xFF) {
      break;
    }
  }
  //密钥区不存在秘钥
  if (usLen == KEYINFO_LEN) {  //检查备份密钥区是否 存在秘钥
    ucFLASH_Read(K21_BAKKEY_ADDR, pucKey, KEYINFO_LEN);
    for (usLen = 0; usLen < KEYINFO_LEN; usLen++) {
      if (*(pucKey + usLen) != 0xFF) {
        break;
      }
    }
    if (KEYINFO_LEN == usLen) {  //备份密钥区也不存在
      //写入默认秘钥
      ucFLASH_Pagerase(K21_KEY_ADDR);
      ucFLASH_Pagewrite(K21_KEY_ADDR, (uint8_t *)PUBKEY_ST, KEYINFO_LEN);
      memcpy(pucKey, PUBKEY_ST, KEYINFO_LEN);
    } else {  //备份区存在，写入密钥区
      ucFLASH_Write(K21_KEY_ADDR, pucKey, KEYINFO_LEN);
    }
  }
}

static secbool bK21_EraseAll(void) {
  uint16_t i;
  uint32_t uiAddr;
  uiAddr = K21_APP_ADDR_START;
  for (i = 0; i < (K21_APP_ADDR_END - K21_APP_ADDR_START) / FLASH_PAGE_SIZE;
       i++) {
    if (0 == ucFLASH_Pagerase(uiAddr)) {
      return false;
    }
    uiAddr += FLASH_PAGE_SIZE;
  }
  return true;
}

// read protobuf integer and advance pointer
static secbool readprotobufint(const uint8_t **ptr, uint32_t *result) {
  *result = 0;
  for (int i = 0; i <= 3; ++i) {
    *result += (**ptr & 0x7F) << (7 * i);
    if ((**ptr & 0x80) == 0) {
      (*ptr)++;
      return sectrue;
    }
    (*ptr)++;
  }
  if (**ptr & 0xF0) {
    // result does not fit into uint32_t
    *result = 0;
    // skip over the rest of the integer
    while (**ptr & 0x80) (*ptr)++;
    (*ptr)++;
    return secfalse;
  }
  *result += (uint32_t)(**ptr) << 28;
  (*ptr)++;
  return sectrue;
}

static void rx_callback(usbd_device *dev, uint8_t ep) {
  (void)ep;
  static uint16_t msg_id = 0xFFFF;
  static uint32_t w;
  static int wi;
  uint8_t *p_buf;
  uint8_t aucBuf[7 + 512];  //保存APDU数据
  uint16_t usBleApVerHex;
  p_buf = packet_buf;

  if (dev != NULL) {
    if (usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_OUT, packet_buf, 64) != 64)
      return;
    memcpy(aucBuf, p_buf, 64);
    if (flash_state == STATE_INTERRPUPT) {
      flash_state = STATE_READY;
      flash_pos = 0;
    }
  }
  if (flash_state == STATE_END) {
    return;
  }

  if (flash_state == STATE_READY || flash_state == STATE_OPEN ||
      flash_state == STATE_FLASHSTART || flash_state == STATE_CHECK ||
      flash_state == STATE_INTERRPUPT) {
    if (p_buf[0] != '?' || p_buf[1] != '#' ||
        p_buf[2] != '#') {  // invalid start - discard
      return;
    }
    // struct.unpack(">HL") => msg, size
    msg_id = (p_buf[3] << 8) + p_buf[4];
  }

  if (flash_state == STATE_READY || flash_state == STATE_OPEN) {
    if (msg_id == 0x0000) {  // Initialize message (id 0)
      send_msg_features(dev);
      flash_state = STATE_OPEN;
      return;
    }
    // add if upgrade bootloader program.at 22.0818
    if (msg_id == 0x0088) {
      w = PTYP_lBERamDWord(p_buf + 5);
      if (w != 0x02) {  // WrongLength
        send_msg_failure(dev);
        return;
      }
      uint16_t new_verison = 0;
      new_verison = PTYP_iBERamWord(p_buf + 9);
      if (new_verison > BOOT_VERSION_HEX) {
        send_msg_success(dev);
      } else {
        send_msg_failure(dev);
      }
      return;
    }

    if (msg_id == 0x0082) {  //获取版本号 130
      if (false == bSE_GetVersion(aucBuf)) {
        send_msg_failure(dev);
        return;
      }
      send_msg_version(dev, aucBuf);
    }
    if (msg_id == 0x0008) {  // The last command
      flash_state = STATE_END;
      //设置蓝牙APP版本号
      if (false == bSE_SetBLEAppVersion(BLEAPP_VERSION)) {
        send_msg_failure(dev);
        return;
      }
      //设置版本号
      if (false == bSE_SetVersion()) {
        send_msg_failure(dev);
        return;
      }
      //设置APP存在标志 防止升级过程中意外插拔生效
      if (0 == ucFLASH_Pagerase(K21_APP_EXIST_ADDR)) {
        send_msg_failure(dev);
        return;
      }
      send_msg_success(dev);
      layoutBootLoaderProgress((bootloader_image)NULL, 100);
      delay_ms(timer1s);
      //显示升级完成
      layoutBootLoaderPage(BLCG, "Succeed", "Press any key to continue");
      return;
    }
    if (msg_id == 0x0083) {  //设备签名指令 131
      w = PTYP_lBERamDWord(p_buf + 5);
      if ((w > 0x20) || (w == 0)) {  // WrongLength
        send_msg_failure(dev);
        flash_state = STATE_END;
        layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
        return;
      }
      memcpy(aucBuf, p_buf + 9, 32);
      if (false == bSE_DevSign(aucBuf)) {
        send_msg_failure(dev);
        flash_state = STATE_END;
        layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
      } else {
        send_msg_signrst(dev, aucBuf);
      }
      return;
    }
    if (msg_id == 0x0084) {  //获取证书指令 132
      bSE_GetCert((uint8_t *)FW_HEADER);
      send_msg_cer(dev);
    }

    if (msg_id == 0x0037) {  // GetFeatures message (id 55)
      // send_msg_features(dev);
      send_msg_Revfeatures(dev);
      return;
    }
    if (msg_id == 0x0001) {  // Ping message (id 1)
      send_msg_success(dev);
      return;
    }
  }

  if (flash_state == STATE_OPEN) {
    if (msg_id == 0x0006) {  // FirmwareErase message (id 6)
      bool proceed = false;
      if (false == ucIsConfirmed) {
        layoutBootLoaderPage(BLSJ, "Confirm to start the upgrade? ", NULL);
        layoutBootLoaderConfirm();
        delay_ms(timer1s);
        proceed = waitButtonRespBoot((KEY_PWON | KEY_NEXT), 500);
        if (proceed) {
          ucIsConfirmed = true;
          // 只有确认以后才可以设置正式进入升级模式并且保证蓝牙不能重复进入升级模式
          if (BLE_INTO_UPG_FLAG != g_vsBootFlgs.uiBleBotExt) {
            g_vsBootFlgs.uiK21AppExt = K21_INTO_BOT_FLAG;
            g_vsBootFlgs.uiBleBotExt = BLE_INTO_UPG_FLAG;
            BOOT_DISABLE_INTERRUPTS;
            ucFLASH_Pagerase(K21_APP_EXIST_ADDR);
            ucFLASH_Pagewrite(K21_APP_EXIST_ADDR, (uint8_t *)&g_vsBootFlgs,
                              sizeof(BOTFLGSTR));
            BOOT_ENABILE_INTERRUPTS;
          }
          // 确保升级的平滑性需要在升级boot完后不需要再次要求进入升级模式.
          if (memcmp((uint8_t *)(K21_RAM_END - 4), "nbup", 4) == 0) {
            memset((uint8_t *)(K21_RAM_END - 4), 0xFF, 4);
          } else {
            // 需要蓝牙芯片进入升级模式
            if (bBLE_GetBLEAppVersion(BLEAPP_VERSION)) {
              usBleApVerHex = (((uint16_t)(BLEAPP_VERSION[0] << 8)) & 0xff00) |
                              BLEAPP_VERSION[1];
              if (usBleApVerHex > BLE_OLDFIRVERSION) {
                // 设置蓝牙关闭进入升级模式
                SET_BLE_PREPARE(BLE_UPG);
              }
            }
          }
        } else {
          flash_state = STATE_END;
          send_msg_failure(dev);
          // 超时提示失败
          layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
        }
        layoutBootLoaderPage(BLSJ, "Upgrading... ", NULL);
      } else {  // 只确认一次
        proceed = true;
      }
      if (proceed) {
        send_msg_success(dev);
        flash_state = STATE_FLASHSTART;
      }
      return;
    }
  }

  if (flash_state == STATE_FLASHSTART) {
    if (msg_id == 0x0007) {    // FirmwareUpload message (id 7)
      if (p_buf[9] != 0x0a) {  // invalid contents
        send_msg_failure(dev);
        flash_state = STATE_END;
        layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
        return;
      }
#if 0
      //检测版本是否检测通过
      if(ucVersionChecked != 0x01)
      {
        flash_state = STATE_END;
        layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
        return;        
      }
#endif
      // read payload length  `
      const uint8_t *p = p_buf + 10;
      if (flash_pos) {
        flash_pos = 0;
      }
      if (readprotobufint(&p, &flash_len) != sectrue) {  // integer too large
        send_msg_failure(dev);
        flash_state = STATE_END;
        layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
        return;
      }
      // check firmware magic
      if ((memcmp(p, &FIRMWARE_MAGIC_NEW, 4) != 0) &&
          (memcmp(p, &FIRMWARE_MAGIC_BLE, 4) != 0) &&
          (memcmp(p, &FIRMWARE_MAGIC_SE, 4) != 0) &&
          (memcmp(p, &FIRMWARE_MAGIC_FLASH, 4) != 0) &&
          (memcmp(p, &FIRMWARE_MAGIC_SKEY, 4) != 0) &&
          (memcmp(p, &FIRMWARE_MAGIC_BKEY, 4) != 0) &&
          (memcmp(p, &FIRMWARE_MAGIC_KKEY, 4) != 0)) {
        send_msg_failure(dev);
        flash_state = STATE_END;
        layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
        return;
      }
      if (memcmp(p, &FIRMWARE_MAGIC_NEW, 4) == 0) {
        update_mode = UPDATE_ST;
      } else if (memcmp(p, &FIRMWARE_MAGIC_BLE, 4) == 0) {
        update_mode = UPDATE_BLE;
      } else if (memcmp(p, &FIRMWARE_MAGIC_SE, 4) == 0) {
        update_mode = UPDATE_SE;
      } else if (memcmp(p, &FIRMWARE_MAGIC_FLASH, 4) == 0) {
        update_mode = UPDATE_FLASH;
      } else if (memcmp(p, &FIRMWARE_MAGIC_SKEY, 4) == 0) {
        update_mode = UPDATE_SKEY;
      } else if (memcmp(p, &FIRMWARE_MAGIC_BKEY, 4) == 0) {
        update_mode = UPDATE_BKEY;
      } else if (memcmp(p, &FIRMWARE_MAGIC_KKEY, 4) == 0) {
        update_mode = UPDATE_KKEY;
      }

      if (flash_len <= FLASH_FWHEADER_LEN) {  // firmware is too small
        send_msg_failure(dev);
        flash_state = STATE_END;
        layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
        return;
      }
      if (UPDATE_ST == update_mode) {
        if (flash_len >
            FLASH_FWHEADER_LEN + K21_APP_MAX_SIZE) {  // firmware is too big
          send_msg_failure(dev);
          flash_state = STATE_END;
          layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
          return;
        }
      } else if (UPDATE_BLE == update_mode) {
        // do nothing
      } else if (UPDATE_SE == update_mode) {
        // do nothing
      } else if (UPDATE_FLASH == update_mode) {
        // do nothing
      } else {  //升级秘钥时，数据长度为512
        if (flash_len > FLASH_FWHEADER_LEN + 516) {  // firmware is too big
          send_msg_failure(dev);
          flash_state = STATE_END;
          layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
          return;
        }
      }
      memzero(FW_HEADER, sizeof(FW_HEADER));
      memzero(FW_CHUNK, sizeof(FW_CHUNK));
      flash_state = STATE_FLASHING;
      flash_pos = 0;
      chunk_idx = 0;
      w = 0;
      wi = 0;
      while (p < p_buf + 64) {
        // assign byte to first byte of uint32_t w
        w = (w >> 8) | (((uint32_t)*p) << 24);
        wi++;
        if (wi == 4) {
          FW_HEADER[flash_pos / 4] = w;
          flash_pos += 4;
          wi = 0;
        }
        p++;
      }
//版本检测放在单独的指令里，这个版本检测，测试没问题
#if 0
      //check version
      ucRet = checkVersion();
      if(VERSION_OLD_ERROR == ucRet)
      {
        //版本低，发送下一个固件文件
        send_msg_failure_versionOLD(dev);
        flash_state = STATE_END;
      }
      else
      if(VERSION_TRANS_ERROR == ucRet)
      {
        send_msg_failure(dev);
        flash_state = STATE_END;
      }
#endif
      // 此处显示升级进程开始
      g_uiUpFileLens = 0;
      if (false == ucIsUpgraded) {
        ucIsUpgraded = true;
        layoutBootLoaderProgress(BLSJ, 0);
      }
      return;
    }
    return;
  }
  if (flash_state == STATE_INTERRPUPT) {
    if (msg_id == 0x0000) {
      send_msg_features(dev);
      flash_state = STATE_FLASHSTART;
      timer_out_set(timer_out_oper, timer1s * 5);
      return;
    }
  }
  if (flash_state == STATE_FLASHING) {
    if (p_buf[0] != '?') {  // invalid contents
      send_msg_failure(dev);
      flash_state = STATE_END;
      layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
      return;
    }
    const uint8_t *p = p_buf + 1;
    while (p < p_buf + 64 && flash_pos < flash_len) {
      // assign byte to first byte of uint32_t w
      w = (w >> 8) | (((uint32_t)*p) << 24);
      wi++;
      if (wi == 4) {
        if (flash_pos < FLASH_FWHEADER_LEN) {
          FW_HEADER[flash_pos / 4] = w;
          flash_pos += 4;
          wi = 0;
          if (FLASH_FWHEADER_LEN == flash_pos) {
            //更新SE，获取HASH和签名，发给SE进行固件升级
            // if ((UPDATE_SE == update_mode) || (UPDATE_BLE == update_mode)){
            if ((UPDATE_SE == update_mode) || (UPDATE_BLE == update_mode) ||
                (UPDATE_SKEY == update_mode) || (UPDATE_BKEY == update_mode)) {
              delay_ms(100);
              //更新SE确保SE在Boot状态
              if (false == bSE_GetState(aucBuf)) {
                send_msg_failure(dev);
                flash_state = STATE_END;
                layoutBootLoaderPage(BLSB, "Failed",
                                     "Press any key to continue");
                return;
              }
              if (((aucBuf[0] != 0x00) && (aucBuf[0] != 0x33) &&
                   (aucBuf[0] != 0x55))) {
                send_msg_failure(dev);
                flash_state = STATE_END;
                layoutBootLoaderPage(BLSB, "Failed",
                                     "Press any key to continue");
                return;
              }
              // SE处于APP状态，报错退出
              if (0x55 == aucBuf[0]) {
                if (false == bSE_Back2Boot()) {
                  send_msg_failure(dev);
                  flash_state = STATE_END;
                  layoutBootLoaderPage(BLSB, "Failed",
                                       "Press any key to continue");
                  return;
                }
                // SE jump into boot ,delay 1000
                delay_ms(1000);
              }
              // 80FC000160 hash(32) sign(64)
              if (FALSE == bSE_Update(0x01)) {
                send_msg_failure(dev);
                flash_state = STATE_END;
                layoutBootLoaderPage(BLSB, "Failed",
                                     "Press any key to continue");
                return;
              }
            } else if ((UPDATE_FLASH == update_mode) ||
                       (UPDATE_ST == update_mode) ||
                       (UPDATE_KKEY == update_mode)) {
              uint8_t pubkey[KEYINFO_LEN];
              vK21_ReadPubkey(pubkey);
              // check signrst
              if (0 != ecdsa_verify_digest(
                           &secp256k1, pubkey,
                           ((image_header *)FW_HEADER)->sig1,
                           ((image_header *)FW_HEADER)->hashes)) {  // failure
                flash_state = STATE_END;
                layoutBootLoaderPage(BLSB, "Failed",
                                     "Press any key to continue");
                return;
              }
              // hash initialization
              sha256_Init(&ctx);
              if (UPDATE_ST == update_mode) {
                // Erase k21 FLASH
                if (false == bK21_EraseAll()) {
                  flash_state = STATE_END;
                  show_halt("K21 erase app flash", "failed.");
                  return;
                }
                g_uiExFlashAddr = K21_APP_ADDR_START;
                //版本号,存储在K21bin文件的头中，偏移为30，保存下来
                memcpy(version, ((uint8_t *)FW_HEADER) + 30, 2);
              } else if (UPDATE_FLASH == update_mode) {
                // do nothing
              }
            }
          }
        } else {  // RAM中暂存固件数据
          FW_CHUNK[((flash_pos - FLASH_FWHEADER_LEN) % FW_CHUNK_SIZE) / 4] = w;
          flash_pos += 4;
          wi = 0;
          if (UPDATE_KKEY == update_mode) {
            if (flash_pos == (FLASH_FWHEADER_LEN + 512)) {
              sha256_Update(&ctx, (uint8_t *)FW_CHUNK, 512);
              sha256_Final(&ctx, hash);
              if (memcmp(hash, ((image_header *)FW_HEADER)->hashes, 32) != 0) {
                send_msg_failure(dev);
                show_unplug("FLASH firmware", "update failed.");
                flash_state = STATE_END;
                return;
              } else {  // 写入K21秘钥
                ucFLASH_Pagerase(K21_BAKKEY_ADDR);
                ucFLASH_Pagewrite(K21_BAKKEY_ADDR, (uint8_t *)FW_CHUNK,
                                  KEYINFO_LEN);
                ucFLASH_Pagerase(K21_KEY_ADDR);
                ucFLASH_Pagewrite(K21_KEY_ADDR, (uint8_t *)FW_CHUNK,
                                  KEYINFO_LEN);
              }
            }
          } else if (UPDATE_ST == update_mode) {
            if (((flash_pos - FLASH_FWHEADER_LEN) % FW_CHUNK_SIZE == 0)) {
              if (0 == ucFLASH_Write(g_uiExFlashAddr, (uint8_t *)FW_CHUNK,
                                     FW_CHUNK_SIZE)) {
                flash_state = STATE_END;
                layoutBootLoaderPage(BLSB, "Failed",
                                     "Press any key to continue");
                return;
              }
              g_uiExFlashAddr += FW_CHUNK_SIZE;
              sha256_Update(&ctx, (uint8_t *)FW_CHUNK, FW_CHUNK_SIZE);
              // 更新进度百分比
              g_uiUpFileLens += FW_CHUNK_SIZE;
              if (g_uiUpFileLens / (flash_len / 40)) {
                g_uiUpFileLens = 0;
                g_uiUpPercent += 1;
              }
              layoutBootLoaderProgress((bootloader_image)NULL, g_uiUpPercent);
            }
          } else if ((UPDATE_SE == update_mode) ||
                     (UPDATE_BLE == update_mode) ||
                     (UPDATE_BKEY == update_mode) ||
                     (UPDATE_SKEY == update_mode)) {
            // SE每512字节进行一次更新
            if ((((flash_pos - FLASH_FWHEADER_LEN) % 512) == 0x00) &&
                (flash_pos > FLASH_FWHEADER_LEN)) {
              if ((UPDATE_SE == update_mode) || (UPDATE_BLE == update_mode)) {
                if (false == bSE_Update(0x02)) {  // 80FC0002000200 固件数据
                  send_msg_failure(dev);
                  flash_state = STATE_END;
                  layoutBootLoaderPage(BLSB, "Failed",
                                       "Press any key to continue");
                  return;
                }
              } else {
                if (false == bSE_Update(0x05)) {  // 80FC0002000500 固件数据
                  send_msg_failure(dev);
                  flash_state = STATE_END;
                  show_halt("SE update 2", "failed.");
                  return;
                }
              }
              // 更新进度百分比
              g_uiUpFileLens += 512;
              if (g_uiUpFileLens / (flash_len / 20)) {
                g_uiUpFileLens = 0;
                g_uiUpPercent += 1;
              }
              layoutBootLoaderProgress((bootloader_image)NULL, g_uiUpPercent);
            }
          } else if (UPDATE_FLASH == update_mode) {
            if ((((flash_pos - FLASH_FWHEADER_LEN) % 256) == 0x00) &&
                (flash_pos >
                 FLASH_FWHEADER_LEN)) {  // EXFLASH每256字节进行一次更新
              uint8_t *pucTmp;
              pucTmp = (uint8_t *)FW_CHUNK +
                       ((flash_pos - 256 - FLASH_FWHEADER_LEN) % FW_CHUNK_SIZE);
              memcpy(aucBuf, pucTmp, 256);
              vNAND_FlashPageProgram(g_uiExFlashAddr, aucBuf, 256);
              g_uiExFlashAddr += 256;
              sha256_Update(&ctx, aucBuf, 256);
              // 更新进度百分比
              g_uiUpFileLens += 256;
              if (g_uiUpFileLens / (flash_len / 20)) {
                g_uiUpFileLens = 0;
                g_uiUpPercent += 1;
              }
              layoutBootLoaderProgress((bootloader_image)NULL, g_uiUpPercent);
            }
          }
        }
        if ((flash_pos - FLASH_FWHEADER_LEN) % FW_CHUNK_SIZE ==
            0) {  // finished the whole chunk
          memzero((uint8_t *)FW_CHUNK, sizeof(FW_CHUNK));
        }
      }
      p++;
    }
    if (flash_pos == flash_len) {  // flashing done
      if (UPDATE_ST == update_mode) {
        sha256_Final(&ctx, hash);
        if (memcmp(hash, ((image_header *)FW_HEADER)->hashes, 32) != 0) {
          send_msg_failure(dev);
          layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
          flash_state = STATE_END;
          return;
        } else {
          //设置版本号放到最后一条指令中
          delay_ms(1000);
          send_msg_success(dev);
        }
      } else if ((UPDATE_BLE == update_mode) || (UPDATE_SE == update_mode)) {
        if (false == bSE_Update(3)) {  // 80FC000300 SE固件升级最后一步
          send_msg_failure(dev);
          flash_state = STATE_END;
          layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
          return;
        }
        delay_ms(1000);                       // SE jump into app ,delay 1000
        if (false == bSE_GetState(aucBuf)) {  // 80FC000000 获取SE状态
          send_msg_failure(dev);
          flash_state = STATE_END;
          layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
          return;
        }
        if (aucBuf[0] != 0x33) {
          send_msg_failure(dev);
          flash_state = STATE_END;
          layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
          return;
        } else {
          if (UPDATE_BLE ==
              update_mode) {  // 如果是升级蓝牙，获取蓝牙APP版本号，写到SE中
            //获取蓝牙APP版本
            //升级结束时将蓝牙APP版本号写入到SE中，保证SE处于APP状态
            if (false == bBLE_GetBLEAppVersion(BLEAPP_VERSION)) {
              send_msg_failure(dev);
              flash_state = STATE_END;
              layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
              return;
            }
          }
          if (false == bSE_AcitveAPP()) {  // 激活se app
            send_msg_failure(dev);
            flash_state = STATE_END;
            layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
            return;
          }
          delay_ms(100);                        // after active se jump into app
          if (false == bSE_GetState(aucBuf)) {  // get status after active
            send_msg_failure(dev);
            flash_state = STATE_END;
            layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
            return;
          }
          if ((0x55 != aucBuf[0]) &&
              (0x00 != aucBuf[0])) {  // 00：APP升级Boot成功；55:APP升级成功
            send_msg_failure(dev);
            flash_state = STATE_END;
            layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
            return;
          }
        }
        // flash_state = STATE_END;
        delay_ms(500);
        send_msg_success(dev);
      } else if (UPDATE_FLASH == update_mode) {
        sha256_Final(&ctx, hash);
        if (memcmp(hash, ((image_header *)FW_HEADER)->hashes, 32) != 0) {
          send_msg_failure(dev);
          layoutBootLoaderPage(BLSB, "Failed", "Press any key to continue");
          flash_state = STATE_END;
        } else {
          delay_ms(1000);
          send_msg_success(dev);
        }
      } else {
        //升级SE KEY\BKEY\KKEY成功
        send_msg_success(dev);
      }
      //初始化相关变量准备更新下一个固件
      boot_init_static_para();
      flash_state = STATE_READY;
      return;
    }
  }
}

static void set_config(usbd_device *dev, uint16_t wValue) {
  (void)wValue;
  usbd_ep_setup(dev, ENDPOINT_ADDRESS_IN, USB_ENDPOINT_ATTR_INTERRUPT, 64, 0);
  usbd_ep_setup(dev, ENDPOINT_ADDRESS_OUT, USB_ENDPOINT_ATTR_INTERRUPT, 64,
                rx_callback);
}

usbd_device *g_pvsUsbDev = NULL;
static usbd_device *usbd_dev = NULL;
static uint8_t usbd_control_buffer[256] __attribute__((aligned(2)));

static const struct usb_device_capability_descriptor *capabilities_landing[] = {
    (const struct usb_device_capability_descriptor
         *)&webusb_platform_capability_descriptor_landing,
};

static const struct usb_device_capability_descriptor
    *capabilities_no_landing[] = {
        (const struct usb_device_capability_descriptor
             *)&webusb_platform_capability_descriptor_no_landing,
};

static const struct usb_bos_descriptor bos_descriptor_landing = {
    .bLength = USB_DT_BOS_SIZE,
    .bDescriptorType = USB_DT_BOS,
    .bNumDeviceCaps =
        sizeof(capabilities_landing) / sizeof(capabilities_landing[0]),
    .capabilities = capabilities_landing};

static const struct usb_bos_descriptor bos_descriptor_no_landing = {
    .bLength = USB_DT_BOS_SIZE,
    .bDescriptorType = USB_DT_BOS,
    .bNumDeviceCaps =
        sizeof(capabilities_no_landing) / sizeof(capabilities_no_landing[0]),
    .capabilities = capabilities_no_landing};

static void usbInit(bool firmware_present) {
  usbd_dev =
      usbd_init(&otgfs_usb_driver._mk21_usb_hard_dirver, &dev_descr, &config,
                usb_strings, sizeof(usb_strings) / sizeof(const char *),
                usbd_control_buffer, sizeof(usbd_control_buffer));

  usbd_register_set_config_callback(usbd_dev, set_config);
  usb21_setup(usbd_dev, firmware_present ? &bos_descriptor_no_landing
                                         : &bos_descriptor_landing);
  webusb_setup(usbd_dev, "connect.keypal.pro");
  winusb_setup(usbd_dev, USB_INTERFACE_INDEX_MAIN);
  // /*Global pointer assignment*/
  g_pvsUsbDev = usbd_dev;
  /*usb hardware init*/
  otgfs_usb_driver._usb_hard_init(true);
}

/*static*/ void checkButtons(void) {
  if (btn_final) {
    return;
  }
  uint16_t state = keys_get(KEY_PWON);
  state |= keys_get(KEY_BACK);
  if ((btn_left == false) && (state & KEY_BACK)) {
    btn_left = true;
    /**/
  }
  if ((btn_right == false) && (state & KEY_PWON) != KEY_PWON) {
    btn_right = true;
    /**/
  }
  if (btn_left && btn_right) {
    btn_final = true;
  }
}

void usbSleep(uint32_t millis) {
  volatile uint32_t uiStaCnt, uiRefCnt, uiTimeOut;

  BOOT_ENABILE_INTERRUPTS;
  /*大约10ms*/
  uiTimeOut = 0x00029810;
  uiStaCnt = timer_ms();
  while (uiTimeOut--) {
    uiRefCnt = timer_ms();
    if ((uiRefCnt - uiStaCnt) < millis) {
      usbd_poll(g_pvsUsbDev);
    } else
      break;
  }
}

void usbLoop(void) {
  bool firmware_present = firmware_present_new();
  g_uiUpPercent = 0;
  ucIsConfirmed = false;
  ucIsUpgraded = false;
  // BLEAPP版本号初始化为0000
  BLEAPP_VERSION[0] = BLEAPP_VERSION[1] = 0x00;
  boot_init_static_para();
  usbInit(firmware_present);
  //
  for (;;) {
    usbd_poll(g_pvsUsbDev);
    // if (!firmware_present &&
    //     (flash_state == STATE_READY || flash_state == STATE_OPEN)) {
    //   checkButtons();
    // }
  }
}
