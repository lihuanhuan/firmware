#include "gd32f4xx.h"
#include "systick.h"

void led_test1(void) {
  uint8_t reTimes = 0;
  /* configure systick */
  gd32_systick_config();

  /* enable the LEDs GPIO clock */
  rcu_periph_clock_enable(RCU_GPIOE);

  /* configure LED2 GPIO port */
  gpio_mode_set(GPIOE, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO_PIN_2);
  gpio_output_options_set(GPIOC, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO_PIN_2);
  /* reset LED2 GPIO pin */
  gpio_bit_reset(GPIOE, GPIO_PIN_2);

  reTimes = 0;

  while (reTimes < 5) {
    /* turn on LED2 */
    gpio_bit_set(GPIOE, GPIO_PIN_2);
    gd32_delay_1ms(1000);

    /* turn off LED2 */
    gpio_bit_reset(GPIOE, GPIO_PIN_2);
    gd32_delay_1ms(1000);
    reTimes++;
  }
}

void led_test2(void) {
  uint8_t reTimes = 0;
  /* configure systick */
  gd32_systick_config();

  /* enable the LEDs GPIO clock */
  rcu_periph_clock_enable(RCU_GPIOE);

  /* configure LED2 GPIO port */
  gpio_mode_set(GPIOE, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO_PIN_3);
  gpio_output_options_set(GPIOE, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO_PIN_3);
  /* reset LED2 GPIO pin */
  gpio_bit_reset(GPIOE, GPIO_PIN_3);

  reTimes = 0;

  while (reTimes < 5) {
    /* turn on LED2 */
    gpio_bit_set(GPIOE, GPIO_PIN_3);
    gd32_delay_1ms(1000);

    /* turn off LED2 */
    gpio_bit_reset(GPIOE, GPIO_PIN_3);
    gd32_delay_1ms(1000);
    reTimes++;
  }
}
