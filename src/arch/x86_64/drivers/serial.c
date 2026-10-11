#include "serial64.h"
#include "serial.h"
#include "protos.h"
#include "panic64.h"

static inline void outb(u16 port, u8 value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline u8 inb(u16 port) {
    u8 value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

void serial64_putc(char value) {
        //
    // Non-blocking: write the byte WITHOUT waiting on the LSR (inb 0x3FD).
    //
    // On KVM, an LSR *read* (inb 0x3FD) taken while a second CPU or the AP's
    // SeaBIOS firmware is driving the SAME emulated UART can wedge the
    // VM-exit (it never returns) and hang the BSP for good - a bounded spin
    // does not help, because the spin counter only advances when the inb
    // returns. So we drop the LSR poll entirely: if the transmit holding
    // register is busy the byte is lost, but the CPU never stalls. When the
    // UART is uncontended (single CPU, or the AP already parked in hlt) the
    // bytes flow cleanly, which is exactly when our important markers go out.
    //
    outb(0x3F8, (u8)value);
}

void serial64_write(const char *text) {
    while (*text) serial64_putc(*text++);
}

void serial64_hex(u64 value) {
    static const char digits[] = "0123456789ABCDEF";
    for (int shift = 60; shift >= 0; shift -= 4)
        serial64_putc(digits[(value >> shift) & 0xF]);
}

// Decimal, for the numbers a reader compares against a table. Hex is the
// right form for a bit pattern and the wrong one for a rate.
void serial64_dec(u64 value) {
    char digits[20];
    u32 count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (count)
        serial64_putc(digits[--count]);
}

void serial_write(const char *text) {
    serial64_write(text);
}

void panic_str(const char *text) {
    panic64_halt(text);
}
