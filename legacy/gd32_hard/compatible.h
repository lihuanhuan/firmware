#ifndef COMPATIBLE_H
#define COMPATIBLE_H
#if GD32F470
//oled spi
#define OLED_SPI_BASE   SPI2
#define RCC_OLED_SPI    RCC_SPI2
#define RCC_OLED_DATA   RCC_GPIOI     
#define RCC_OLED_DC     RCC_GPIOH

#define OLED_DC_PORT GPIOH
#define OLED_DC_PIN GPIO13   // PH13 | Data/Command
#define OLED_CS_PORT GPIOI
#define OLED_CS_PIN GPIO0    // PI0 | SPI Select
#define OLED_RST_PORT GPIOH
#define OLED_RST_PIN GPIO15  // PH15 | Reset display
#define OLED_SCK_PIN GPIO1
#define OLED_MOSI_PIN GPIO3

#else

//oled spi
#define OLED_SPI_BASE   SPI1
#define RCC_OLED_SPI    RCC_SPI1
#define RCC_OLED_DATA   RCC_GPIOA    
#define RCC_OLED_DC     RCC_GPIOB
#ifdef OLD_PCB
#define OLED_DC_PORT GPIOA
#define OLED_DC_PIN GPIO2  // PA2 | Data/Command
#define OLED_CS_PORT GPIOA
#define OLED_CS_PIN GPIO4  // PA4 | SPI Select
#define OLED_RST_PORT GPIOA
#define OLED_RST_PIN GPIO3  // PA3 | Reset display
#define OLED_SCK_PIN GPIO5
#define OLED_MOSI_PIN GPIO7
#else
#define OLED_DC_PORT GPIOB
#define OLED_DC_PIN GPIO0  // PB0 | Data/Command
#define OLED_CS_PORT GPIOA
#define OLED_CS_PIN GPIO4  // PA4 | SPI Select
#define OLED_RST_PORT GPIOB
#define OLED_RST_PIN GPIO1  // PB1 | Reset display
#define OLED_SCK_PIN GPIO5
#define OLED_MOSI_PIN GPIO7
#endif

#endif//GD32F470
#endif//COMPATIBLE_H