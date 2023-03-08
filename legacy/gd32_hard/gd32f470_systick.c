/*!
    \file  systick.c
    \brief the systick configuration file
*/

/*
    Copyright (C) 2016 GigaDevice

    2016-10-19, V1.0.0, demo for GD32F4xx
*/

#include "gd32f4xx.h"
#include "systick.h"

//
__IO uint32_t g_uiSysTickCunt;

/*!
    \brief      configure systick
    \param[in]  none
    \param[out] none
    \retval     none
*/
void gd32_systick_config(void) {
  /* setup systick timer for 1000Hz interrupts */
  if (SysTick_Config(SystemCoreClock / 1000U)) {
    /* capture error */
    while (1) {
    }
  }
  /* configure the systick handler priority */
  NVIC_SetPriority(SysTick_IRQn, 0x00U);
}

/*!
    \brief      delay a time in milliseconds
    \param[in]  count: count in milliseconds
    \param[out] none
    \retval     none
*/
void gd32_delay_1ms(uint32_t count) {
  g_uiSysTickCunt = count;

  while (0U != g_uiSysTickCunt) {
  }
}

/*!
    \brief      delay decrement
    \param[in]  none
    \param[out] none
    \retval     none
*/
void gd32_delay_decrement(void) {
  if (0U != g_uiSysTickCunt) {
    g_uiSysTickCunt--;
  }
}
