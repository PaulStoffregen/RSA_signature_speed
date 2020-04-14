# RSA Signature Speed - Simple CPU Performance Benchmark

Measures the time required to compute a digital signature (SHA256 + RSA2048) of a string.

| Board                           | Seconds |
| ------------------------------- | :-----: |
| Teensy 4.0                      |  0.085  |
| Teensy 3.6                      |  0.474  |
| Sparkfun ESP32 Thing            |  0.518  |
| Metro M4 Grand Central          |  0.840  |
| Teensy 3.5                      |  0.909  |
| Teensy 3.2                      |  1.325  |
| Arduino Due                     |  1.901  |
| STM32 Blue Pill (STM32F103C8T6) |  2.268  |
| Arduino Zero                    |  9.638  |

(smaller numbers are better)

