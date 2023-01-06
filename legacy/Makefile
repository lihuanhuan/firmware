ifneq ($(EMULATOR),1)
ifneq ($(GD32F470),1)
OBJS += startup.o
else
OBJS += gd32_hard/startup_gd32f470.o
OBJS += gd32_hard/system_gd32f470.o
OBJS += gd32_hard/gd32f470_irq.o
OBJS += gd32_hard/gd32f470_systick.o
OBJS += gd32_hard/led_test.o
endif
endif

OBJS += buttons.o
OBJS += common.o
OBJS += flash.o
OBJS += layout.o
OBJS += oled.o
OBJS += random_delays.o
OBJS += rng.o

ifneq ($(EMULATOR),1)
OBJS += setup.o
OBJS += sys.o
OBJS += si2c.o
OBJS += usart.o
OBJS += nordic_dfu.o
OBJS += ble.o
OBJS += trans_fifo.o

OBJS += segger_rtt/SEGGER_RTT.o
OBJS += segger_rtt/SEGGER_RTT_printf.o
OBJS += segger_rtt/rtt_log.o

OBJS += mi2c.o
OBJS += se_chip.o

endif

OBJS += util.o
OBJS += memory.o
OBJS += supervise.o

ifneq ($(EMULATOR),1)
OBJS += timer.o
endif

OBJS += usb_standard.o
OBJS += usb21_standard.o
OBJS += webusb.o
OBJS += winusb.o

OBJS += gen/bitmaps.o
OBJS += gen/fonts.o
OBJS += gen/prompt.o

libtrezor.a: $(OBJS)

include Makefile.include

libtrezor.a:
	@printf "  AR      $@\n"
	$(Q)$(AR) rcs $@ $^

.PHONY: vendor

vendor:
	git submodule update --init --recursive
