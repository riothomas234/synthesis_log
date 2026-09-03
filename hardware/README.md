# Raspberry Pi 3 B+ to MSI MS-4462 TPM

This is the bench wiring for the 12-1-pin SPI MS-4462 module marked
`VER:1.03`. All logic and power are 3.3 V.

## Module connector orientation

Hold the module component-side up with `MSI` readable and look directly into
the connector. The blocked hole is second from the left in the top row:

```text
                 MS-4462 socket, mating face

              left                         right
top row       [12 IRQ] [10 KEY] [8 RST#] [6 CLK] [4 MOSI] [2 CS#]
bottom row    [11 NC ] [ 9 NC ] [7 GND ] [5 NC ] [3 MISO] [1 3V3]
                         ^ blocked hole
```

Pins 5, 9, and 11 are reserved. Leave them disconnected. Pin 12 is the
optional interrupt and can also remain disconnected for initial polling-mode
operation.

## Circuit

```text
Raspberry Pi 3 B+                         MSI MS-4462

physical 1   3V3  ----------------------- pin 1  SPI power
physical 24  CE0  ----------------------- pin 2  CS#
physical 21  MISO <----------------------- pin 3  MISO
physical 19  MOSI -----------------------> pin 4  MOSI
physical 23  SCLK -----------------------> pin 6  SPI clock
physical 6   GND  ------------------------ pin 7  ground

                         3V3
                          |
                        10 kohm
                          |
                          +---------------- pin 8  RST#
                          |
                        1 uF temporary
                          |
                         GND

pin 5  reserved -------------------------- no connection
pin 9  reserved -------------------------- no connection
pin 10 key ------------------------------- blocked
pin 11 reserved -------------------------- no connection
pin 12 IRQ# ------------------------------ no connection initially
```

The temporary 1 uF reset capacitor with the 10 kohm pull-up gives an RC time
constant of about 10 ms. Replace it with a 100 nF (`0.1 uF`, marking `104`)
capacitor when available. If the 1 uF capacitor is polarized, connect its
positive lead to RST# and negative lead to GND.

The module has local surface-mount capacitors. An optional 1 uF ceramic can be
placed directly between pins 1 and 7 for extra breadboard supply bypassing. Do
not use a 100 uF capacitor on RST#.

## Before applying power

1. Disconnect power from the Pi.
2. Use continuity mode to confirm pin 7 reaches the ground side of the
   module's local capacitors.
3. Confirm there is no short between module pins 1 and 7.
4. Recheck that the blocked socket position is pin 10 and that no connections
   are mirrored.
5. Keep the SPI wires short, preferably under 15 cm for the first test.
6. Apply 3.3 V only. Never connect this module to a Pi 5 V pin.

