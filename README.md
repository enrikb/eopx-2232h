# Quirks needed to make eopx run with an FTDI 2232H chip

## Problem

I wanted to use an off-the-shelf FTDI 2232 board to implement a programmer device for experimentation
with EnOcean TCM300 modules. The goal was to be able to use programming tools available from the
[EnOcean website](https://www.enocean.com/). The partial schematics used to connect the modules to an
FTDI 2232D based programmer can be found in the EDK 350 User Manual also available from this website.

Most break-out boards available today are using FTDI 2232H chips. There seem to be small imcompatibilities
regarding the MPSSE 0x88 and 0x89 commands. While the older devices seem to use `GPIOH1` to trigger the 
commands, the 'H' variant seems to use `GPIOL1` only.

Unfortunately, it turned out that the module's 'ready' feedback signal (`ADIO7`) in the original
schematic connects to pin `GPIOH1` of the 2232. On the 2232H, this function seems to be provided on pin
`GPIOL1`, though. The original programmer design uses the same pin as 'programming LED', i.e. drives it
as output. Obviously, when configured as output, the pin can't be used as 'ready' signal at the same time.

## Solution

I managed to use [frida](https://frida.re/) to patch the MPSSE program sequences to leave `GPIOL1`
configured as input. Further, it patches the FTDI library's response to report an ID 4 chip when it
detects an ID 6 chip.
