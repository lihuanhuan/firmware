/*!
    \file  systick.h
    \brief the header file of systick
*/

/*
    Copyright (C) 2016 GigaDevice

    2016-10-19, V1.0.0, demo for GD32F4xx
*/

#ifndef SYS_TICK_H
#define SYS_TICK_H

#include <stdint.h>

/* configure systick */
void gd32_systick_config(void);
/* delay a time in milliseconds */
void gd32_delay_1ms(uint32_t count);
/* delay decrement */
void gd32_delay_decrement(void);

#endif /* SYS_TICK_H */
