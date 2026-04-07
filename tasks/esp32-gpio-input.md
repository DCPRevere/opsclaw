# ESP32 GPIO input reads are stubbed

`firmware/esp32/src/main.rs:141` always returns `Ok(0)`. Implement real input pin reading by storing `InputPin` drivers per pin.
