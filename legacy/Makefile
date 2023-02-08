ifneq ($(EMULATOR),1)
OBJS += startup.o
ifeq ($(GD32F470),1)
OBJS += gd32_hard/system_gd32f470.o
endif
endif

OBJS += buttons.o
OBJS += common.o
ifneq ($(GD32F470),1)
OBJS += flash.o
else
OBJS += gd32_hard/flash_gd32.o
endif
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
ifneq ($(GD32F470),1)
OBJS += memory.o
else
OBJS += gd32_hard/memory_gd32.o
endif
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
