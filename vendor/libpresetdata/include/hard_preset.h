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

#ifndef __HARD_PRESET_H__
#define __HARD_PRESET_H__

#include <stdbool.h>
#include <stdint.h>

extern bool bPresetDataWrite(uint8_t *pBuf);

extern bool bPresetDataRead(uint8_t *pBuf);

#endif
