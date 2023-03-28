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

#include "../flash.h"
#include <libopencm3/usb/usbd.h>

#include <stdint.h>
#include <string.h>

#include "ble.h"
#include "bootloader.h"
#include "buttons.h"
#include "ecdsa.h"
#include "layout.h"
#include "layout_boot.h"
#include "memory.h"
#include "memzero.h"
#include "oled.h"
#include "rng.h"
#include "secbool.h"
#include "secp256k1.h"
#include "sha2.h"
#include "si2c.h"
#include "signatures.h"
#include "sys.h"
#include "updateble.h"
#include "usb.h"
#include "util.h"

#include "timer.h"
#include "usart.h"

#include "nordic_dfu.h"

#include "usb21_standard.h"
#include "webusb.h"
#include "winusb.h"
#include "mi2c.h"
#include "usb_desc.h"
#include "compatible.h"

#define PTYP_iBERamWord(address)                         \
  ((((uint16_t)(*((uint8_t *)address) << 8)) & 0xFF00) + \
   ((uint16_t)(*(uint8_t *)((uint8_t *)(address) + 1)) & 0x00FF))
#define PTYP_lBERamDWord(address)                                \
  ((((uint32_t)(PTYP_iBERamWord(address)) << 16) & 0xFFFF0000) + \
   ((uint32_t)(PTYP_iBERamWord((uint8_t *)(address) + 2)) & 0x0000FFFF))

enum {
  STATE_READY,
  STATE_OPEN,
  STATE_FLASHSTART,
  STATE_FLASHING,
  STATE_INTERRPUPT,
  STATE_CHECK,
  STATE_END,
};

#define NORDIC_BLE_UPDATE 1

#define UPDATE_BLE 0x5A
#define UPDATE_ST 0x55
#define UPDATE_SE 0x56
uint32_t flash_pos = 0, flash_len = 0;
static uint32_t chunk_idx = 0;
static char flash_state = STATE_READY;

static uint8_t packet_buf[64] __attribute__((aligned(4)));

#include "usb_send.h"

static uint32_t FW_HEADER[FLASH_FWHEADER_LEN / sizeof(uint32_t)];
static uint32_t FW_CHUNK[FW_CHUNK_SIZE / sizeof(uint32_t)];
static uint8_t update_mode = 0;
static uint8_t version[2] = {0};
static uint16_t usCerLen;

static void flash_enter(void) { return; }

static void flash_exit(void) { return; }

static inline bool se_get_firmware_version(uint8_t *resp) {
  uint8_t ucVerCmd[5] = {0x00, 0xf7, 0x00, 00, 0x02};
  static uint8_t ver[2] = {0};
  uint16_t ver_len = sizeof(ver);

  if (false == bMI2CDRV_SendData(ucVerCmd, sizeof(ucVerCmd))) {
    return false;
  }

  delay_ms(5);
  if (false == bMI2CDRV_ReceiveData(resp, &ver_len)) {
    return false;
  }

  return true;
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
  // get se status
  if (false == bMI2CDRV_SendData(aucBuf, 5)) {
    return false;
  }
  delay_ms(100);
  usLen = 0xFF;
  if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
    return false;
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
  // se go to second boot status
  if (false == bMI2CDRV_SendData(aucBuf, 5)) {
    return false;
  }
  delay_ms(10);
  usLen = 0xFF;
  if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
    return false;
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
  // se active app
  if (false == bMI2CDRV_SendData(aucBuf, 5)) {
    return false;
  }
  delay_ms(10);
  usLen = 0xFF;
  if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
    return false;
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

  // send steps
  if (0x01 == ucStep) {
    aucBuf[4] = 0x60;
    memcpy(aucBuf + 5, &(((image_header *)FW_HEADER)->hashes), 32);
    memcpy(aucBuf + 5 + 32, &(((image_header *)FW_HEADER)->sig1), 64);
    usLen = 101;
    if (false == bMI2CDRV_SendData(aucBuf, usLen)) {
      return false;
    }
    delay_ms(50);
  } else if ((0x02 == ucStep) || (0x05 == ucStep)) {
    aucBuf[5] = 0x02;
    aucBuf[6] = 0x00;
    pucTmp = (uint8_t *)FW_CHUNK + ((flash_pos - 512) % FW_CHUNK_SIZE);
    memcpy(aucBuf + 7, pucTmp, 512);
    usLen = 519;
    if (false == bMI2CDRV_SendData(aucBuf, usLen)) {
      return false;
    }
    delay_ms(5);
  } else if (0x03 == ucStep) {
    usLen = 5;
    if (false == bMI2CDRV_SendData(aucBuf, usLen)) {
      return false;
    }
    delay_ms(50);
  }
  // recv data from se
  usLen = 0xFF;
  if (false == bMI2CDRV_ReceiveData(aucBuf, &usLen)) {
    return false;
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

#include "usb_erase.h"

static void check_and_write_chunk(void) {
  uint32_t offset = (chunk_idx == 0) ? FLASH_FWHEADER_LEN : 0;
  uint32_t chunk_pos = flash_pos % FW_CHUNK_SIZE;
  if (chunk_pos == 0) {
    chunk_pos = FW_CHUNK_SIZE;
  }
  uint8_t hash[32] = {0};
  SHA256_CTX ctx = {0};
  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t *)FW_CHUNK + offset, chunk_pos - offset);
  if (chunk_pos < 64 * 1024) {
    // pad with FF
    for (uint32_t i = chunk_pos; i < 64 * 1024; i += 4) {
      sha256_Update(&ctx, (const uint8_t *)"\xFF\xFF\xFF\xFF", 4);
    }
  }
  sha256_Final(&ctx, hash);

  const image_header *hdr = (const image_header *)FW_HEADER;
  // invalid chunk sent
  if (0 != memcmp(hash, hdr->hashes + chunk_idx * 32, 32)) {
    flash_state = STATE_END;
    show_halt("Error installing", "firmware.");
    return;
  }

  // all done
  if (flash_len == flash_pos) {
    // check remaining chunks if any
    for (uint32_t i = chunk_idx + 1; i < 16; i++) {
      // hash should be empty if the chunk is unused
      if (!mem_is_empty(hdr->hashes + 32 * i, 32)) {
        flash_state = STATE_END;
        show_halt("Error installing", "firmware.");
        return;
      }
    }
  }

  memzero(FW_CHUNK, sizeof(FW_CHUNK));
  chunk_idx++;
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
  // static int old_was_signed;
  uint8_t *p_buf;
  uint8_t se_version[2];
  uint8_t apduBuf[7 + 512];  // set se apdu data context

  p_buf = packet_buf;

  if (dev != NULL) {
    if (usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_OUT, packet_buf, 64) != 64)
      return;
    host_channel = CHANNEL_USB;
    // cache apdu context
    memcpy(apduBuf, packet_buf, 64);
    //
    if (flash_state == STATE_INTERRPUPT) {
      flash_state = STATE_READY;
      flash_pos = 0;
    }
  } else {
    host_channel = CHANNEL_SLAVE;
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

    if (msg_id == 0x0088) {  // add if upgrade bootloader
      w = PTYP_lBERamDWord(p_buf + 5);
      if (w != 0x02) {  // WrongLength
        show_unplug("Upgrade Boot", "aborted.");
        send_msg_failure(dev, 4);  // Failure_ActionCancelled
        shutdown();
        return;
      }
      uint16_t new_verison = 0;
      new_verison = PTYP_iBERamWord(p_buf + 9);
      if (new_verison > BOOT_VERSION_HEX) {
        send_msg_success(dev);
      } else {
        show_unplug("Upgrade Boot", "aborted.");
        send_msg_failure(dev, 4);  // Failure_ActionCancelled
        shutdown();
      }
      return;
    }

    if (msg_id == 0x0082) {  // get firmware version 130
      if (false == bSE_GetVersion(apduBuf)) {
        show_unplug("Upgrade SE", "aborted.");
        send_msg_failure(dev, 1);  // Failure_ActionCancelled
        shutdown();
        return;
      }
      send_msg_version(dev, apduBuf);
    }

    if (msg_id == 0x0083) {  // se cert sign 131
      w = PTYP_lBERamDWord(p_buf + 5);
      if ((w > 0x20) || (w == 0)) {  // WrongLength
        send_msg_failure(dev, 4);
        flash_state = STATE_END;
        return;
      }
      memcpy(apduBuf, p_buf + 9, 32);
      if (false == bSE_DevSign(apduBuf)) {
        show_unplug("Upgrade SE", "aborted.");
        send_msg_failure(dev, 1);  // Failure_ActionCancelled
        shutdown();
      } else {
        send_msg_signrst(dev, apduBuf);
      }
      return;
    }

    if (msg_id == 0x0084) {  // get se cert 132
      bSE_GetCert((uint8_t *)FW_HEADER);
      send_msg_cer(dev);
    }

    if (msg_id == 0x0008) {  // The last command
      flash_state = STATE_END;
      if (false == bSE_SetVersion()) {  // set se version
        send_msg_failure(dev, 1);
        return;
      }
      //设置APP存在标志 防止升级过程中意外插拔生效
      // if (0 == ucFLASH_Pagerase(K21_APP_EXIST_ADDR)) {
      //   send_msg_failure(dev);
      //   return;
      // }
      send_msg_success(dev);
      return;
    }

    if (msg_id == 0x0037) {  // GetFeatures message (id 55)
      send_msg_features(dev);
      return;
    }
    if (msg_id == 0x0001) {  // Ping message (id 1)
      send_msg_success(dev);
      return;
    }
    if (msg_id == 0x0005) {  // WipeDevice message (id 5)
      layoutDialog(&bmp_icon_question, "Cancel", "Confirm", NULL,
                   "Do you really want to", "wipe the device?", NULL,
                   "All data will be lost.", NULL, NULL);
      bool but = waitButtonResponse(BTN_PIN_YES, default_oper_time);
      if (host_channel == CHANNEL_SLAVE) {
      } else {
        if (but) {
          // TODO
          erase_code_progress();
          //
          flash_state = STATE_END;
          show_unplug("Device", "successfully wiped.");
          send_msg_success(dev);

        } else {
          flash_state = STATE_END;
          show_unplug("Device wipe", "aborted.");
          send_msg_failure(dev, 4);  // Failure_ActionCancelled
          shutdown();
        }
      }
      return;
    }
    if (msg_id != 0x0006 && msg_id != 0x0010) {
      send_msg_failure(dev, 1);  // Failure_UnexpectedMessage
      return;
    }
  }

  if (flash_state == STATE_OPEN) {
    if (msg_id == 0x0006) {  // FirmwareErase message (id 6)
      volatile bool proceed = false;
      if (firmware_present_new()) {
        layoutDialog(&bmp_icon_question, "Abort", "Continue", NULL,
                     "Install new", "firmware?", NULL, "Never do this without",
                     "your recovery card!", NULL);
        proceed = waitButtonResponse(BTN_PIN_YES, default_oper_time);
      } else {
        proceed = true;
      }
      if (proceed) {
        // check whether the current firmware is signed (old or new method)
        // if (firmware_present_new()) {
        //   const image_header *hdr =
        //       (const image_header *)FLASH_PTR(FLASH_FWHEADER_START);
        //   old_was_signed =
        //       signatures_new_ok(hdr, NULL) & check_firmware_hashes(hdr);
        //   old_was_signed = SIG_OK;
        // } else if (firmware_present_old()) {
        //   old_was_signed = signatures_old_ok();
        // } else {
        //   old_was_signed = SIG_FAIL;
        // }
        send_msg_success(dev);
        flash_state = STATE_FLASHSTART;
        timer_out_set(timer_out_oper, timer1s * 5);
      } else {
        send_msg_failure(dev, 4);  // Failure_ActionCancelled
        flash_state = STATE_END;
        show_unplug("Firmware installation", "aborted.");
        shutdown();
      }
      return;
    } else if (msg_id == 0x0010) {  // FirmwareErase message (id 16)
      bool proceed = false;
      layoutDialog(&bmp_icon_question, "Abort", "Continue", NULL, "Install ble",
                   "firmware?", NULL, NULL, NULL, NULL);
      proceed = waitButtonResponse(BTN_PIN_YES, default_oper_time);
      if (proceed) {
        erase_ble_code_progress();
        send_msg_success(dev);
        flash_state = STATE_FLASHSTART;
        timer_out_set(timer_out_oper, timer1s * 5);
      } else {
        send_msg_failure(dev, 4);
        flash_state = STATE_END;
        show_unplug("Firmware installation", "aborted.");
        shutdown();
      }
      return;
    }
    send_msg_failure(dev, 1);  // Failure_UnexpectedMessage
    return;
  }

  if (flash_state == STATE_FLASHSTART) {
    if (msg_id == 0x0000) {  // end resume state
      send_msg_features(dev);
      flash_state = STATE_OPEN;
      flash_pos = 0;
      return;
    } else if (msg_id == 0x0007) {  // FirmwareUpload message (id 7)
      if (p_buf[9] != 0x0a) {       // invalid contents
        send_msg_failure(dev, 9);   // Failure_ProcessError
        flash_state = STATE_END;
        show_halt("Error installing", "firmware.");
        return;
      }
      // read payload length
      const uint8_t *p = p_buf + 10;
      if (flash_pos) {
        flash_pos = 0;
      }
      if (readprotobufint(&p, &flash_len) != sectrue) {  // integer too large
        send_msg_failure(dev, 9);                        // Failure_ProcessError
        flash_state = STATE_END;
        show_halt("Firmware is", "too big.");
        return;
      }
      // check firmware magic
      if ((memcmp(p, &FIRMWARE_MAGIC_NEW, 4) != 0) &&
          (memcmp(p, &FIRMWARE_MAGIC_BLE, 4) != 0) &&
          (memcmp(p, &FIRMWARE_MAGIC_SE, 4) != 0)) {
        send_msg_failure(dev, 9);  // Failure_ProcessError
        flash_state = STATE_END;
        show_halt("Wrong firmware", "header.");
        return;
      }
      if (memcmp(p, &FIRMWARE_MAGIC_NEW, 4) == 0) {
        update_mode = UPDATE_ST;
      } else if (memcmp(p, &FIRMWARE_MAGIC_BLE, 4) == 0) {
        update_mode = UPDATE_BLE;
      } else {
        update_mode = UPDATE_SE;
      }

      if (flash_len <= FLASH_FWHEADER_LEN) {  // firmware is too small
        send_msg_failure(dev, 9);             // Failure_ProcessError
        flash_state = STATE_END;
        show_halt("Firmware is", "too small.");
        return;
      }
      if (UPDATE_ST == update_mode) {
        if (flash_len >
            FLASH_FWHEADER_LEN + FLASH_APP_LEN) {  // firmware is too big
          send_msg_failure(dev, 9);                // Failure_ProcessError
          flash_state = STATE_END;
          show_halt("Firmware is", "too big");
          return;
        }
      } else if (UPDATE_BLE == update_mode) {
        if (flash_len >
            FLASH_FWHEADER_LEN + FLASH_BLE_MAX_LEN) {  // firmware is too big
          send_msg_failure(dev, 9);                    // Failure_ProcessError
          flash_state = STATE_END;
          show_halt("Firmware is", "too small.");
          return;
        }
      } else if (UPDATE_SE == update_mode) {
        // do nothing
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
      return;
    } else {                     // add test 0221
      send_msg_failure(dev, 1);  // Failure_UnexpectedMessage
    }
    return;
  }
  if (flash_state == STATE_INTERRPUPT) {  // adjust struct
    if (msg_id == 0x0000) {
      send_msg_failure(dev, 9);  // Failure_ProcessError
      flash_state = STATE_FLASHSTART;
      timer_out_set(timer_out_oper, timer1s * 5);
      return;
    }
  }

  if (flash_state == STATE_FLASHING) {
    if (p_buf[0] != '?') {       // invalid contents
      send_msg_failure(dev, 9);  // Failure_ProcessError
      flash_state = STATE_END;
      show_halt("Error installing", "firmware.");
      return;
    }
    timer_out_set(timer_out_oper, timer1s * 5);
    static uint8_t flash_anim = 0;
    if (flash_anim % 32 == 4) {
      layoutProgress("INSTALLING ... Please wait",
                     1000 * flash_pos / flash_len);
    }
    flash_anim++;

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
            if (UPDATE_SE == update_mode) {
              delay_ms(100);
              // check se version
              uint16_t current_version, incoming_version;
              if (false == se_get_firmware_version(se_version)) {
                show_unplug("Update SE", "aborted.");
                send_msg_failure(dev, 4);  // Failure_ActionCancelled
                shutdown();
                return;
              }
              current_version = PTYP_iBERamWord(se_version);
              incoming_version = (uint16_t)((image_header *)FW_HEADER)->version;
              if (current_version ==
                  incoming_version) {  // doesn't update se firmware
                flash_state = STATE_END;
                show_unplug("Update SE", "aborted.");
                send_msg_success(dev);
                shutdown();
                return;
              }

              //更新SE确保SE在Boot状态
              if (false == bSE_GetState(apduBuf)) {
                show_unplug("Update SE", "aborted.");
                send_msg_failure(dev, 4);  // Failure_ActionCancelled
                shutdown();
                return;
              }
              if (((apduBuf[0] != 0x00) && (apduBuf[0] != 0x33) &&
                   (apduBuf[0] != 0x55))) {
                flash_state = STATE_END;
                show_unplug("Update SE", "aborted.");
                send_msg_failure(dev, 4);  // Failure_ActionCancelled
                shutdown();
              }
              // SE处于APP状态，报错退出
              if (0x55 == apduBuf[0]) {
                if (false == bSE_Back2Boot()) {
                  show_unplug("Update SE", "aborted.");
                  send_msg_failure(dev, 4);  // Failure_ActionCancelled
                  shutdown();
                  return;
                }
                // SE jump into boot mode ,it need delay 1000
                delay_ms(1000);
              }
              // 80FC000160 hash(32) sign(64)
              if (FALSE == bSE_Update(0x01)) {
                flash_state = STATE_END;
                show_unplug("Update SE", "aborted.");
                send_msg_failure(dev, 4);  // Failure_ActionCancelled
                shutdown();
                return;
              }
            } else if (UPDATE_ST == update_mode) {
              // TODO erase mcu app firmware code
              erase_code_progress();
            } else if (UPDATE_BLE == update_mode) {
              // TODO erase ble firmware storge addr
              erase_ble_code_progress();
            }
          }
        } else {
          FW_CHUNK[(flash_pos % FW_CHUNK_SIZE) / 4] = w;
          flash_enter();
          if (UPDATE_ST == update_mode) {
            flash_write_word_item(FLASH_FWHEADER_START + flash_pos, w);
          } else if (UPDATE_BLE == update_mode) {
            flash_write_word_item(FLASH_BLE_ADDR_START + flash_pos, w);
          } else if (UPDATE_SE == update_mode) {
            // it will be offset
            flash_pos += 4;
            wi = 0;
            // SE每512字节进行一次更新
            if ((((flash_pos - FLASH_FWHEADER_LEN) % 512) == 0x00) &&
                (flash_pos > FLASH_FWHEADER_LEN)) {
              if (UPDATE_SE == update_mode) {
                if (false == bSE_Update(0x02)) {  // 80FC0002000200 固件数据
                  flash_state = STATE_END;
                  show_unplug("Update SE", "aborted.");
                  send_msg_failure(dev, 4);  // Failure_ActionCancelled
                  shutdown();
                  return;
                }
              }
            }
          } else {
            // do nothing
          }
          flash_exit();
          if (UPDATE_SE != update_mode) {
            // it will be offset
            flash_pos += 4;
            wi = 0;
          }
        }
        // TODO check chunk
        if (UPDATE_ST == update_mode) {
          if (flash_pos % FW_CHUNK_SIZE == 0) {
            check_and_write_chunk();
          }
        }
      }
      p++;
    }
    // flashing done
    if (flash_pos == flash_len) {
      if (UPDATE_ST == update_mode) {
        // flush remaining data in the last chunk
        if (flash_pos % FW_CHUNK_SIZE > 0) {
          check_and_write_chunk();
        }
      }
      flash_state = STATE_CHECK;
      if (UPDATE_ST == update_mode) {
        const image_header *hdr = (const image_header *)FW_HEADER;
        if (SIG_OK != signatures_new_ok(hdr, NULL)) {
          send_msg_buttonrequest_firmwarecheck(dev);
          return;
        }
      } else if (UPDATE_SE == update_mode) {
        if (false == bSE_Update(3)) {  // 80FC000300 SE固件升级最后一步
          flash_state = STATE_END;
          show_unplug("Update SE", "aborted.");
          send_msg_failure(dev, 4);  // Failure_ActionCancelled
          shutdown();
          return;
        }
        delay_ms(1000);                        // SE jump into app ,delay 1000
        if (false == bSE_GetState(apduBuf)) {  // 80FC000000 获取SE状态
          flash_state = STATE_END;
          show_unplug("Update SE", "aborted.");
          send_msg_failure(dev, 4);  // Failure_ActionCancelled
          shutdown();
          return;
        }
        if (apduBuf[0] != 0x33) {
          flash_state = STATE_END;
          show_unplug("Update SE", "aborted.");
          send_msg_failure(dev, 4);  // Failure_ActionCancelled
          shutdown();
          return;
        }

        if (false == bSE_AcitveAPP()) {  // enable se app
          flash_state = STATE_END;
          show_unplug("Update SE", "aborted.");
          send_msg_failure(dev, 4);  // Failure_ActionCancelled
          shutdown();
          return;
        }
        delay_ms(100);                         // after active se jump into app
        if (false == bSE_GetState(apduBuf)) {  // get status after active
          flash_state = STATE_END;
          show_unplug("Update SE", "aborted.");
          send_msg_failure(dev, 4);  // Failure_ActionCancelled
          shutdown();
          return;
        }
        if ((0x55 != apduBuf[0]) &&
            (0x00 != apduBuf[0])) {  // 00：APP升级Boot成功；55:APP升级成功
          flash_state = STATE_END;
          show_unplug("Update SE", "aborted.");
          send_msg_failure(dev, 4);  // Failure_ActionCancelled
          shutdown();
          return;
        }
      }
    }
  }
  if (flash_state == STATE_CHECK) {
    timer_out_set(timer_out_oper, 0);
    if (UPDATE_ST == update_mode) {
      // use the firmware header from RAM
      const image_header *hdr = (const image_header *)FW_HEADER;

      bool hash_check_ok;
      // show fingerprint of unsigned firmware
      if (SIG_OK != signatures_new_ok(hdr, NULL)) {
        if (msg_id != 0x001B) {  // ButtonAck message (id 27)
          return;
        }
        uint8_t hash[32] = {0};
        compute_firmware_fingerprint(hdr, hash);
        layoutFirmwareFingerprint(hash);
        hash_check_ok = waitButtonResponse(BTN_PIN_YES, default_oper_time);
      } else {
        hash_check_ok = true;
      }

      layoutProgress("Programing ... Please wait", 1000);

      // wipe storage if:
      /*
        TODO do nothing
      */

      flash_enter();
      // write firmware header only when hash was confirmed
      if (hash_check_ok) {
        for (size_t i = 0; i < FLASH_FWHEADER_LEN / sizeof(uint32_t); i++) {
          flash_write_word_item(FLASH_FWHEADER_START + i * sizeof(uint32_t),
                                FW_HEADER[i]);
        }
      } else {
        for (size_t i = 0; i < FLASH_FWHEADER_LEN / sizeof(uint32_t); i++) {
          flash_write_word_item(FLASH_FWHEADER_START + i * sizeof(uint32_t), 0);
        }
      }
      flash_exit();
      flash_state = STATE_END;
      if (hash_check_ok) {
        show_unplug("New firmware", "successfully installed.");
        send_msg_success(dev);
        shutdown();
      } else {
        layoutDialog(&bmp_icon_warning, NULL, NULL, NULL,
                     "Firmware installation", "aborted.", NULL,
                     "You need to repeat", "the procedure with",
                     "the correct firmware.");
        send_msg_failure(dev, 9);  // Failure_ProcessError
        shutdown();
      }
      return;
    } else if (UPDATE_BLE == update_mode) {
      flash_state = STATE_END;
      i2c_set_wait(false);
      send_msg_success(dev);
      layoutProgress("Updating ... Please wait", 1000);
      delay_ms(500);  // important!!! delay for nordic reset

      uint32_t fw_len = flash_len - FLASH_FWHEADER_LEN;
      bool update_status = false;
#if BLE_SWD_UPDATE
      update_status = bUBLE_UpdateBleFirmware(
          fw_len, FLASH_BLE_ADDR_START + FLASH_FWHEADER_LEN, ERASE_ALL);

#else
      uint8_t *p_init = (uint8_t *)FLASH_INIT_DATA_START;
      uint32_t init_data_len = p_init[0] + (p_init[1] << 8);
#if NORDIC_BLE_UPDATE
      update_status = updateBle(p_init + 4, init_data_len,
                                (uint8_t *)FLASH_BLE_FIRMWARE_START,
                                fw_len - FLASH_INIT_DATA_LEN);
#else
      (void)fw_len;
      (void)init_data_len;
      update_status = false;
#endif
#endif
      if (update_status == false) {
        layoutDialog(&bmp_icon_warning, NULL, NULL, NULL, "ble installation",
                     "aborted.", NULL, "You need to repeat",
                     "the procedure with", "the correct firmware.");
      } else {
        show_unplug("ble firmware", "successfully installed.");
      }
      delay_ms(1000);
      shutdown();
    } else {
      send_msg_success(dev);
      show_unplug("se firmware", "successfully installed.");
    }
  }
}
static void set_config(usbd_device *dev, uint16_t wValue) {
  (void)wValue;

  usbd_ep_setup(dev, ENDPOINT_ADDRESS_IN, USB_ENDPOINT_ATTR_INTERRUPT, 64, 0);
  usbd_ep_setup(dev, ENDPOINT_ADDRESS_OUT, USB_ENDPOINT_ATTR_INTERRUPT, 64,
                rx_callback);
}

static usbd_device *usbd_dev;
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
  usbd_dev = usbd_init(&otgfs_usb_driver_onekey, &dev_descr, &config,
                       usb_strings, sizeof(usb_strings) / sizeof(const char *),
                       usbd_control_buffer, sizeof(usbd_control_buffer));
  usbd_register_set_config_callback(usbd_dev, set_config);
  usb21_setup(usbd_dev, firmware_present ? &bos_descriptor_no_landing
                                         : &bos_descriptor_landing);
  webusb_setup(usbd_dev, "onekey.so");
  winusb_setup(usbd_dev, USB_INTERFACE_INDEX_MAIN);
}

static void checkButtons(void) {
  static bool btn_left = false, btn_right = false, btn_final = false;
  if (btn_final) {
    return;
  }
  uint16_t state = gpio_get(BTN_PORT, BTN_PIN_YES);
  state |= gpio_get(BTN_PORT_NO, BTN_PIN_NO);
  if ((btn_left == false) && (state & BTN_PIN_NO)) {
    btn_left = true;
    oledBox(0, 0, 3, 3, true);
    oledRefresh();
  }
  if ((btn_right == false) && (state & BTN_PIN_YES) != BTN_PIN_YES) {
    btn_right = true;
    oledBox(OLED_WIDTH - 4, 0, OLED_WIDTH - 1, 3, true);
    oledRefresh();
  }
  if (btn_left && btn_right) {
    btn_final = true;
  }
}

static void i2cSlavePoll(void) {
  volatile uint32_t total_len, len;
  if (i2c_recv_done) {
    while (1) {
      total_len = fifo_lockdata_len(&i2c_fifo_in);
      if (total_len == 0) break;
      len = total_len > 64 ? 64 : total_len;
      fifo_read_lock(&i2c_fifo_in, packet_buf, len);
      rx_callback(NULL, 0);
    }
    i2c_recv_done = false;
  }
}

void usbLoop(void) {
  bool firmware_present = firmware_present_new();
  usbInit(firmware_present);
  for (;;) {
    ble_update_poll();
    usbd_poll(usbd_dev);
    i2cSlavePoll();
    if (!firmware_present &&
        (flash_state == STATE_READY || flash_state == STATE_OPEN)) {
      checkButtons();
    }
    if (flash_state == STATE_FLASHSTART || flash_state == STATE_FLASHING) {
      if (checkButtonOrTimeout(BTN_PIN_NO, timer_out_oper)) {
        flash_state = STATE_INTERRPUPT;
        fifo_flush(&i2c_fifo_in);
        layoutRefreshSet(true);
      }
    }
    if (flash_state == STATE_READY || flash_state == STATE_OPEN ||
        flash_state == STATE_INTERRPUPT)
      layoutBootHome();
  }
}
