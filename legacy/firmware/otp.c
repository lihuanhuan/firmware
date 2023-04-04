/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2019 Pavol Rusnak <stick@satoshilabs.com>
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
#include "otp.h"
#include <stdint.h>
#include "gd32f4xx.h"

#define FLASH_OTP_BASE 0x1FFF7800U
#define FLASH_OTP_LOCK_BASE 0x1FFF7A00U

bool flash_otp_is_locked(uint8_t block) {
  return 0x00 == *(volatile uint8_t *)(FLASH_OTP_LOCK_BASE + block);
}

bool flash_otp_lock(uint8_t block) {
  if (block >= FLASH_OTP_NUM_BLOCKS) {
    return false;
  }
  /* unlock the flash program erase controller */
  fmc_unlock();
  /* clear pending flags */
  fmc_flag_clear(FMC_FLAG_END | FMC_FLAG_OPERR | FMC_FLAG_WPERR |
                 FMC_FLAG_PGMERR | FMC_FLAG_PGSERR);

  if (FMC_READY != fmc_byte_program(FLASH_OTP_LOCK_BASE + block, 0x00)) {
    return false;
  }

  fmc_lock();
  return true;
}

bool flash_otp_read(uint8_t block, uint8_t offset, uint8_t *data,
                    uint8_t datalen) {
  if (block >= FLASH_OTP_NUM_BLOCKS ||
      offset + datalen > FLASH_OTP_BLOCK_SIZE) {
    return false;
  }
  for (uint8_t i = 0; i < datalen; i++) {
    data[i] = *(volatile uint8_t *)(FLASH_OTP_BASE +
                                    block * FLASH_OTP_BLOCK_SIZE + offset + i);
  }
  return true;
}

bool flash_otp_write(uint8_t block, uint8_t offset, const uint8_t *data,
                     uint8_t datalen) {
  if (block >= FLASH_OTP_NUM_BLOCKS ||
      offset + datalen > FLASH_OTP_BLOCK_SIZE) {
    return false;
  }
  /* unlock the flash program erase controller */
  fmc_unlock();
  /* clear pending flags */
  fmc_flag_clear(FMC_FLAG_END | FMC_FLAG_OPERR | FMC_FLAG_WPERR |
                 FMC_FLAG_PGMERR | FMC_FLAG_PGSERR);
  for (uint8_t i = 0; i < datalen; i++) {
    uint32_t address =
        FLASH_OTP_BASE + block * FLASH_OTP_BLOCK_SIZE + offset + i;
    if (FMC_READY != fmc_byte_program(address, data[i])) {
      return false;
    }
  }
  fmc_lock();
  return true;
}
