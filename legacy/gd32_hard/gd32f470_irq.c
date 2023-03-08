/*!
    \file  gd32f4xx_it.c
    \brief interrupt service routines
*/

/*
    Copyright (C) 2016 GigaDevice

    2016-10-19, V1.0.0, demo for GD32F4xx
*/

#include "gd32f4xx_it.h"
#include "systick.h"

/*!
    \brief      this function handles NMI exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
void NMI_Handler(void) {}

/*!
    \brief      this function handles HardFault exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
void HardFault_Handler(void) {
  /* if Hard Fault exception occurs, go to infinite loop */
  while (1) {
  }
}

/*!
    \brief      this function handles MemManage exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
void MemManage_Handler(void) {
  /* if Memory Manage exception occurs, go to infinite loop */
  while (1) {
  }
}

/*!
    \brief      this function handles BusFault exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
void BusFault_Handler(void) {
  /* if Bus Fault exception occurs, go to infinite loop */
  while (1) {
  }
}

/*!
    \brief      this function handles UsageFault exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
void UsageFault_Handler(void) {
  /* if Usage Fault exception occurs, go to infinite loop */
  while (1) {
  }
}

/*!
    \brief      this function handles SVC exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
void SVC_Handler(void) {}

/*!
    \brief      this function handles DebugMon exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
void DebugMon_Handler(void) {}

/*!
    \brief      this function handles PendSV exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
void PendSV_Handler(void) {}

/*!
    \brief      this function handles SysTick exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
void irq_gd32_systick_handler(void) {
  //
  gd32_delay_decrement();
}

/* function declarations */
/* handle I2C0 event interrupt request */
extern void i2c0_event_irq_handler(void);
/* handle I2C0 error interrupt request */
extern void i2c0_error_irq_handler(void);
/* handle I2C1 event interrupt request */
extern void i2c1_event_irq_handler(void);
/* handle I2C1 error interrupt request */
extern void i2c1_error_irq_handler(void);

extern void gd32i2c_ev_recv_isr(void);
extern void gd32i2c_ev_send_isr(void);
extern void gd32si2c_ev_isr(void);

extern void usart1_isr(void);
extern void usart1_Ex_isr(void);

/*!
    \brief      this function handles I2C0 event interrupt request exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
// void I2C0_EV_IRQHandler(void) { i2c0_event_irq_handler(); }

/*!
    \brief      this function handles I2C0 error interrupt request exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
// void I2C0_ER_IRQHandler(void) { i2c0_error_irq_handler(); }

/*!
    \brief      this function handles I2C1 event interrupt request exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
// void I2C1_EV_IRQHandler(void) { gd32si2c_ev_isr(); }

/*!
    \brief      this function handles I2C1 error interrupt request exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
// void I2C1_ER_IRQHandler(void) { i2c1_error_irq_handler(); }

/*!
    \brief      this function handles USART0 exception
    \param[in]  none
    \param[out] none
    \retval     none
*/
// void USART1_IRQHandler(void) { usart1_Ex_isr(); }