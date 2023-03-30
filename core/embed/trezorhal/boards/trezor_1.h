#ifndef _TREZOR_1_H
#define _TREZOR_1_H

#include "displays/vg-2864ksweg01.h"

#define BTN_LEFT_PIN GPIO_PIN_5
#define BTN_LEFT_PORT GPIOC
#define BTN_LEFT_CLK_ENA __HAL_RCC_GPIOC_CLK_ENABLE
#define BTN_RIGHT_PIN GPIO_PIN_2
#define BTN_RIGHT_PORT GPIOC
#define BTN_RIGHT_CLK_ENA __HAL_RCC_GPIOC_CLK_ENABLE

#define OLED_DC_PORT GPIOB
#define OLED_DC_PIN GPIO_PIN_0  // PB0 | Data/Command
#define OLED_DC_CLK_ENA __HAL_RCC_GPIOB_CLK_ENABLE
#define OLED_CS_PORT GPIOA
#define OLED_CS_PIN GPIO_PIN_4  // PA4 | SPI Select
#define OLED_CS_CLK_ENA __HAL_RCC_GPIOA_CLK_ENABLE
#define OLED_RST_PORT GPIOB
#define OLED_RST_PIN GPIO_PIN_1  // PB1 | Reset display
#define OLED_RST_CLK_ENA __HAL_RCC_GPIOB_CLK_ENABLE

#define OLED_SPI SPI1
#define OLED_SPI_AF GPIO_AF5_SPI1
#define OLED_SPI_CLK_ENA __HAL_RCC_SPI1_CLK_ENABLE
#define OLED_SPI_SCK_PORT GPIOA
#define OLED_SPI_SCK_PIN GPIO_PIN_5  // PA5 | SPI SCK
#define OLED_SPI_SCK_CLK_ENA __HAL_RCC_GPIOA_CLK_ENABLE
#define OLED_SPI_MOSI_PORT GPIOA
#define OLED_SPI_MOSI_PIN GPIO_PIN_7  // PA7 | SPI MOSI
#define OLED_SPI_MOSI_CLK_ENA __HAL_RCC_GPIOA_CLK_ENABLE

#endif  //_TREZOR_1_H
