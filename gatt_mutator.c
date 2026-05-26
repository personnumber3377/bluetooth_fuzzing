// gatt_packet_mutator.c
//
// Assumed fuzzer input layout:
//   [mode byte optional-ish][u16 len][ATT/GATT PDU bytes][u16 len][ATT/GATT PDU bytes]...
//
// The parser is deliberately forgiving:
// - If length is too large, clamp to remaining input.
// - If packet is too large, truncate to MAX_PDU_SIZE.
// - If input is random garbage, recover as best as possible.
//
// Build self-test:
//   clang -DMUT_TESTING -O2 -g gatt_packet_mutator.c -o mut_test
//   ./mut_test
//
// Build object for libFuzzer target:
//   clang -O2 -g -c gatt_packet_mutator.c -o gatt_packet_mutator.o
//
// Then link gatt_packet_mutator.o into the fuzzer binary.

// This is if we are putting this via #include "gatt_mutator.c"

#ifdef __cplusplus
extern "C" {
#endif

size_t LLVMFuzzerCustomMutator(
    uint8_t *Data,
    size_t Size,
    size_t MaxSize,
    unsigned Seed);

size_t LLVMFuzzerCustomCrossOver(
    const uint8_t *Data1,
    size_t Size1,
    const uint8_t *Data2,
    size_t Size2,
    uint8_t *Out,
    size_t MaxOutSize,
    unsigned Seed);

#ifdef __cplusplus
}
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_PACKETS 256
#define MAX_PDU_SIZE 512
#define MAX_VALUE_SIZE 256

typedef struct {
    uint16_t len;
    uint8_t data[MAX_PDU_SIZE];
} Packet;

typedef struct {
    uint8_t mode;
    int has_mode;
    Packet packets[MAX_PACKETS];
    size_t count;
} Input;

// ------------------------- RNG -------------------------

static uint32_t rng_next(uint32_t *s)
{
    uint32_t x = *s;
    if (x == 0)
        x = 0x12345678u;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;

    *s = x;
    return x;
}

static uint32_t rnd(uint32_t *s, uint32_t max)
{
    if (max == 0)
        return 0;
    return rng_next(s) % max;
}

static int chance(uint32_t *s, uint32_t one_in)
{
    return rnd(s, one_in) == 0;
}

// ------------------------- byte helpers -------------------------

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint16_t edge_u16(uint32_t *seed)
{
    static const uint16_t vals[] = {
        0x0000, 0x0001, 0x0002, 0x0003,
        0x0004, 0x0005, 0x0007, 0x0008,
        0x000f, 0x0010, 0x0017, 0x0018,
        0x001f, 0x0020, 0x00ff, 0x0100,
        0x0200, 0x03ff, 0x0400, 0x07ff,
        0x0800, 0x0fff, 0x1000, 0x7fff,
        0x8000, 0xfffe, 0xffff
    };

    if (chance(seed, 3))
        return vals[rnd(seed, (uint32_t)(sizeof(vals) / sizeof(vals[0])))];

    return (uint16_t)rnd(seed, 0x10000);
}

static uint16_t sane_handle_pair_start(uint32_t *seed)
{
    uint16_t v = edge_u16(seed);
    if (v == 0)
        v = 1;
    return v;
}

static uint16_t sane_handle_pair_end(uint32_t *seed, uint16_t start)
{
    if (chance(seed, 5)) {
        // intentionally invalid sometimes
        return (uint16_t)rnd(seed, start ? start : 1);
    }

    uint16_t delta = (uint16_t)rnd(seed, 64);
    uint32_t end = (uint32_t)start + delta;
    if (end > 0xffff)
        end = 0xffff;
    if (end == 0)
        end = 1;
    return (uint16_t)end;
}

static uint16_t common_uuid16(uint32_t *seed)
{
    static const uint16_t uuids[] = {
        0x1800, // GAP
        0x1801, // GATT
        0x2a00, // Device Name
        0x2a01, // Appearance
        0x2a04, // PPCP
        0x2800, // Primary Service
        0x2801, // Secondary Service
        0x2802, // Include
        0x2803, // Characteristic Declaration
        0x2901, // User Description
        0x2902, // CCCD
        0x2904  // Presentation Format
    };

    if (chance(seed, 2))
        return uuids[rnd(seed, (uint32_t)(sizeof(uuids) / sizeof(uuids[0])))];

    return edge_u16(seed);
}

static size_t fill_random(uint8_t *out, size_t max, uint32_t *seed)
{
    size_t n = rnd(seed, (uint32_t)(max + 1));
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)rnd(seed, 256);
    return n;
}

// ------------------------- ATT/GATT PDU generator -------------------------

static const uint8_t att_ops[] = {
    0x01, // Error Response
    0x02, // Exchange MTU Request
    0x03, // Exchange MTU Response
    0x04, // Find Information Request
    0x05, // Find Information Response
    0x06, // Find By Type Value Request
    0x07, // Find By Type Value Response
    0x08, // Read By Type Request
    0x09, // Read By Type Response
    0x0a, // Read Request
    0x0b, // Read Response
    0x0c, // Read Blob Request
    0x0d, // Read Blob Response
    0x0e, // Read Multiple Request
    0x0f, // Read Multiple Response
    0x10, // Read By Group Type Request
    0x11, // Read By Group Type Response
    0x12, // Write Request
    0x13, // Write Response
    0x16, // Prepare Write Request
    0x17, // Prepare Write Response
    0x18, // Execute Write Request
    0x19, // Execute Write Response
    0x1b, // Handle Value Notification
    0x1d, // Handle Value Indication
    0x1e, // Handle Value Confirmation
    0x20, // Read Multiple Variable Request
    0x52, // Write Command
    0xd2  // Signed Write Command
};

static void packet_set(Packet *p, const uint8_t *buf, size_t len)
{
    if (len > MAX_PDU_SIZE)
        len = MAX_PDU_SIZE;

    p->len = (uint16_t)len;
    memcpy(p->data, buf, len);
}

static void gen_att_pdu(Packet *p, uint32_t *seed)
{
    uint8_t buf[MAX_PDU_SIZE];
    size_t n = 0;

    uint8_t op = att_ops[rnd(seed, (uint32_t)(sizeof(att_ops) / sizeof(att_ops[0])))];
    buf[n++] = op;

    switch (op) {
        case 0x01: { // Error Response: req opcode, handle, error code
            buf[n++] = att_ops[rnd(seed, (uint32_t)(sizeof(att_ops) / sizeof(att_ops[0])))];
            wr16(buf + n, edge_u16(seed)); n += 2;
            buf[n++] = (uint8_t)rnd(seed, 0x14);
            break;
        }

        case 0x02: // Exchange MTU Request
        case 0x03: { // Exchange MTU Response
            uint16_t mtu;
            static const uint16_t mtus[] = {
                0, 1, 2, 3, 23, 24, 64, 128, 247, 512, 1024, 517, 0xffff
            };
            mtu = mtus[rnd(seed, (uint32_t)(sizeof(mtus) / sizeof(mtus[0])))];
            wr16(buf + n, mtu); n += 2;
            break;
        }

        case 0x04: // Find Information Request: start, end
        case 0x10: { // Read By Group Type Request: start, end, type uuid
            uint16_t start = sane_handle_pair_start(seed);
            uint16_t end = sane_handle_pair_end(seed, start);
            wr16(buf + n, start); n += 2;
            wr16(buf + n, end); n += 2;

            if (op == 0x10) {
                if (chance(seed, 4)) {
                    // 128-bit UUID
                    for (int i = 0; i < 16 && n < MAX_PDU_SIZE; i++)
                        buf[n++] = (uint8_t)rnd(seed, 256);
                } else {
                    wr16(buf + n, common_uuid16(seed)); n += 2;
                }
            }
            break;
        }

        case 0x05: { // Find Information Response: format + repeated handle/uuid
            uint8_t fmt = chance(seed, 3) ? 2 : 1;
            buf[n++] = fmt;
            int count = 1 + (int)rnd(seed, 8);
            for (int i = 0; i < count && n + 4 < MAX_PDU_SIZE; i++) {
                wr16(buf + n, edge_u16(seed)); n += 2;
                if (fmt == 1) {
                    wr16(buf + n, common_uuid16(seed)); n += 2;
                } else {
                    for (int j = 0; j < 16 && n < MAX_PDU_SIZE; j++)
                        buf[n++] = (uint8_t)rnd(seed, 256);
                }
            }
            break;
        }

        case 0x06: { // Find By Type Value Request: start, end, type, value
            uint16_t start = sane_handle_pair_start(seed);
            uint16_t end = sane_handle_pair_end(seed, start);
            wr16(buf + n, start); n += 2;
            wr16(buf + n, end); n += 2;
            wr16(buf + n, common_uuid16(seed)); n += 2;
            n += fill_random(buf + n, MAX_VALUE_SIZE < (MAX_PDU_SIZE - n) ? MAX_VALUE_SIZE : (MAX_PDU_SIZE - n), seed);
            break;
        }

        case 0x07: { // Find By Type Value Response: repeated found handle group
            int count = 1 + (int)rnd(seed, 8);
            for (int i = 0; i < count && n + 4 <= MAX_PDU_SIZE; i++) {
                uint16_t start = sane_handle_pair_start(seed);
                uint16_t end = sane_handle_pair_end(seed, start);
                wr16(buf + n, start); n += 2;
                wr16(buf + n, end); n += 2;
            }
            break;
        }

        case 0x08: { // Read By Type Request: start, end, uuid
            uint16_t start = sane_handle_pair_start(seed);
            uint16_t end = sane_handle_pair_end(seed, start);
            wr16(buf + n, start); n += 2;
            wr16(buf + n, end); n += 2;
            if (chance(seed, 4)) {
                for (int i = 0; i < 16 && n < MAX_PDU_SIZE; i++)
                    buf[n++] = (uint8_t)rnd(seed, 256);
            } else {
                wr16(buf + n, common_uuid16(seed)); n += 2;
            }
            break;
        }

        case 0x09: // Read By Type Response
        case 0x11: { // Read By Group Type Response
            uint8_t elem_len = (uint8_t)(2 + rnd(seed, 32));
            if (chance(seed, 5))
                elem_len = (uint8_t)rnd(seed, 4); // invalid edge
            buf[n++] = elem_len;
            n += fill_random(buf + n, MAX_VALUE_SIZE < (MAX_PDU_SIZE - n) ? MAX_VALUE_SIZE : (MAX_PDU_SIZE - n), seed);
            break;
        }

        case 0x0a: { // Read Request: handle
            wr16(buf + n, edge_u16(seed)); n += 2;
            break;
        }

        case 0x0b: // Read Response
        case 0x0d: // Read Blob Response
        case 0x0f: { // Read Multiple Response
            n += fill_random(buf + n, MAX_VALUE_SIZE < (MAX_PDU_SIZE - n) ? MAX_VALUE_SIZE : (MAX_PDU_SIZE - n), seed);
            break;
        }

        case 0x0c: { // Read Blob Request: handle, offset
            wr16(buf + n, edge_u16(seed)); n += 2;
            wr16(buf + n, edge_u16(seed)); n += 2;
            break;
        }

        case 0x0e: // Read Multiple Request
        case 0x20: { // Read Multiple Variable Request
            int handles = 1 + (int)rnd(seed, 16);
            for (int i = 0; i < handles && n + 2 <= MAX_PDU_SIZE; i++) {
                wr16(buf + n, edge_u16(seed)); n += 2;
            }
            break;
        }

        case 0x12: // Write Request
        case 0x52: { // Write Command
            wr16(buf + n, edge_u16(seed)); n += 2;
            n += fill_random(buf + n, MAX_VALUE_SIZE < (MAX_PDU_SIZE - n) ? MAX_VALUE_SIZE : (MAX_PDU_SIZE - n), seed);
            break;
        }

        case 0xd2: { // Signed Write Command: handle, value, 12-byte signature-ish trailer
            wr16(buf + n, edge_u16(seed)); n += 2;
            size_t value_len = rnd(seed, 64);
            if (n + value_len + 12 > MAX_PDU_SIZE)
                value_len = MAX_PDU_SIZE - n - 12;
            for (size_t i = 0; i < value_len; i++)
                buf[n++] = (uint8_t)rnd(seed, 256);
            for (int i = 0; i < 12 && n < MAX_PDU_SIZE; i++)
                buf[n++] = (uint8_t)rnd(seed, 256);
            break;
        }

        case 0x13: // Write Response
        case 0x19: // Execute Write Response
        case 0x1e: { // Handle Value Confirmation
            break;
        }

        case 0x16: // Prepare Write Request
        case 0x17: { // Prepare Write Response
            wr16(buf + n, edge_u16(seed)); n += 2; // handle
            wr16(buf + n, edge_u16(seed)); n += 2; // offset
            n += fill_random(buf + n, MAX_VALUE_SIZE < (MAX_PDU_SIZE - n) ? MAX_VALUE_SIZE : (MAX_PDU_SIZE - n), seed);
            break;
        }

        case 0x18: { // Execute Write Request: flags
            static const uint8_t flags[] = {0x00, 0x01, 0xff};
            buf[n++] = flags[rnd(seed, (uint32_t)(sizeof(flags) / sizeof(flags[0])))];
            break;
        }

        case 0x1b: // Notification
        case 0x1d: { // Indication
            wr16(buf + n, edge_u16(seed)); n += 2;
            n += fill_random(buf + n, MAX_VALUE_SIZE < (MAX_PDU_SIZE - n) ? MAX_VALUE_SIZE : (MAX_PDU_SIZE - n), seed);
            break;
        }

        default:
            n += fill_random(buf + n, MAX_VALUE_SIZE < (MAX_PDU_SIZE - n) ? MAX_VALUE_SIZE : (MAX_PDU_SIZE - n), seed);
            break;
    }

    packet_set(p, buf, n);
}

// ------------------------- parser/serializer -------------------------

static size_t parse_input(const uint8_t *data, size_t size, Input *in)
{
    memset(in, 0, sizeof(*in));

    if (size == 0)
        return 0;

    // Keep one byte outside the packet stream. In your harness this often influences
    // client/server choice or early FuzzedDataProvider decisions.
    in->has_mode = 1;
    in->mode = data[0];

    size_t pos = 1;
    size_t count = 0;

    while (pos + 2 <= size && count < MAX_PACKETS) {
        uint16_t len = rd16(data + pos);
        pos += 2;

        size_t remain = size - pos;
        if (len > remain)
            len = (uint16_t)remain;

        if (len > MAX_PDU_SIZE)
            len = MAX_PDU_SIZE;

        in->packets[count].len = len;
        memcpy(in->packets[count].data, data + pos, len);

        pos += len;
        count++;
    }

    // If trailing garbage remains and no packet parsed it, turn it into a packet.
    if (count == 0 && size > 1) {
        size_t len = size - 1;
        if (len > MAX_PDU_SIZE)
            len = MAX_PDU_SIZE;
        in->packets[0].len = (uint16_t)len;
        memcpy(in->packets[0].data, data + 1, len);
        count = 1;
    }

    in->count = count;
    return count;
}

static size_t serialize_input(const Input *in, uint8_t *out, size_t max)
{
    size_t pos = 0;

    if (max == 0)
        return 0;

    if (in->has_mode) {
        out[pos++] = in->mode;
    }

    for (size_t i = 0; i < in->count; i++) {
        const Packet *p = &in->packets[i];

        if (pos + 2 > max)
            break;

        size_t len = p->len;
        if (len > MAX_PDU_SIZE)
            len = MAX_PDU_SIZE;

        if (pos + 2 + len > max)
            len = max - pos - 2;

        wr16(out + pos, (uint16_t)len);
        pos += 2;

        memcpy(out + pos, p->data, len);
        pos += len;
    }

    return pos;
}

// ------------------------- mutations -------------------------

static void mutate_packet_bytes(Packet *p, uint32_t *seed)
{
    if (p->len == 0)
        return;

    switch (rnd(seed, 6)) {
        case 0: { // flip byte
            size_t off = rnd(seed, p->len);
            p->data[off] ^= (uint8_t)(1u << rnd(seed, 8));
            break;
        }
        case 1: { // set byte to edge
            static const uint8_t vals[] = {0, 1, 2, 3, 7, 8, 15, 16, 23, 31, 32, 0x7f, 0x80, 0xfe, 0xff};
            size_t off = rnd(seed, p->len);
            p->data[off] = vals[rnd(seed, (uint32_t)(sizeof(vals) / sizeof(vals[0])))];
            break;
        }
        case 2: { // mutate u16
            if (p->len >= 2) {
                size_t off = rnd(seed, p->len - 1);
                wr16(p->data + off, edge_u16(seed));
            }
            break;
        }
        case 3: { // insert byte
            if (p->len < MAX_PDU_SIZE) {
                size_t off = rnd(seed, p->len + 1);
                memmove(p->data + off + 1, p->data + off, p->len - off);
                p->data[off] = (uint8_t)rnd(seed, 256);
                p->len++;
            }
            break;
        }
        case 4: { // delete byte
            if (p->len > 0) {
                size_t off = rnd(seed, p->len);
                memmove(p->data + off, p->data + off + 1, p->len - off - 1);
                p->len--;
            }
            break;
        }
        case 5: { // truncate/extend
            if (chance(seed, 2)) {
                p->len = (uint16_t)rnd(seed, p->len + 1);
            } else if (p->len < MAX_PDU_SIZE) {
                size_t add = rnd(seed, 16);
                if (p->len + add > MAX_PDU_SIZE)
                    add = MAX_PDU_SIZE - p->len;
                for (size_t i = 0; i < add; i++)
                    p->data[p->len++] = (uint8_t)rnd(seed, 256);
            }
            break;
        }
    }
}

static void mutate_opcode(Packet *p, uint32_t *seed)
{
    if (p->len == 0) {
        gen_att_pdu(p, seed);
        return;
    }

    p->data[0] = att_ops[rnd(seed, (uint32_t)(sizeof(att_ops) / sizeof(att_ops[0])))];

    // Occasionally regenerate whole PDU so opcode and payload match.
    if (chance(seed, 2))
        gen_att_pdu(p, seed);
}

extern size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned Seed)
{
    Input in;
    uint32_t seed = Seed ? Seed : 1;

    parse_input(Data, Size, &in);

    if (in.count == 0) {
        in.has_mode = 1;
        in.mode = (uint8_t)rnd(&seed, 256);
        in.count = 1;
        gen_att_pdu(&in.packets[0], &seed);
        return serialize_input(&in, Data, MaxSize);
    }

    switch (rnd(&seed, 10)) {
        case 0: { // mutate mode
            in.mode ^= (uint8_t)(1u << rnd(&seed, 8));
            break;
        }

        case 1: { // byte-level packet mutation
            Packet *p = &in.packets[rnd(&seed, (uint32_t)in.count)];
            mutate_packet_bytes(p, &seed);
            break;
        }

        case 2: { // opcode mutation / regenerate typed PDU
            Packet *p = &in.packets[rnd(&seed, (uint32_t)in.count)];
            mutate_opcode(p, &seed);
            break;
        }

        case 3: { // add semantic packet
            if (in.count < MAX_PACKETS) {
                gen_att_pdu(&in.packets[in.count], &seed);
                in.count++;
            }
            break;
        }

        case 4: { // delete packet
            if (in.count > 0) {
                size_t victim = rnd(&seed, (uint32_t)in.count);
                memmove(&in.packets[victim],
                        &in.packets[victim + 1],
                        (in.count - victim - 1) * sizeof(Packet));
                in.count--;
            }
            break;
        }

        case 5: { // duplicate packet
            if (in.count > 0 && in.count < MAX_PACKETS) {
                size_t src = rnd(&seed, (uint32_t)in.count);
                size_t dst = rnd(&seed, (uint32_t)(in.count + 1));
                memmove(&in.packets[dst + 1],
                        &in.packets[dst],
                        (in.count - dst) * sizeof(Packet));
                in.packets[dst] = in.packets[src];
                in.count++;
            }
            break;
        }

        case 6: { // swap packets
            if (in.count >= 2) {
                size_t a = rnd(&seed, (uint32_t)in.count);
                size_t b = rnd(&seed, (uint32_t)in.count);
                Packet tmp = in.packets[a];
                in.packets[a] = in.packets[b];
                in.packets[b] = tmp;
            }
            break;
        }

        case 7: { // splice bytes between packets
            if (in.count >= 2) {
                Packet *a = &in.packets[rnd(&seed, (uint32_t)in.count)];
                Packet *b = &in.packets[rnd(&seed, (uint32_t)in.count)];

                if (a->len && b->len) {
                    size_t cut_a = rnd(&seed, a->len);
                    size_t cut_b = rnd(&seed, b->len);
                    size_t tail_b = b->len - cut_b;
                    if (cut_a + tail_b > MAX_PDU_SIZE)
                        tail_b = MAX_PDU_SIZE - cut_a;

                    // Causing overlapping stuff...
                    // memcpy(a->data + cut_a, b->data + cut_b, tail_b);
                    memmove(a->data + cut_a,
                        b->data + cut_b,
                        tail_b);
                    a->len = (uint16_t)(cut_a + tail_b);
                }
            }
            break;
        }

        case 8: { // replace packet with generated valid-ish ATT PDU
            Packet *p = &in.packets[rnd(&seed, (uint32_t)in.count)];
            gen_att_pdu(p, &seed);
            break;
        }

        case 9: { // intentionally weird: zero-length or huge-ish packet after serialization fix
            Packet *p = &in.packets[rnd(&seed, (uint32_t)in.count)];
            if (chance(&seed, 2)) {
                p->len = 0;
            } else {
                p->len = MAX_PDU_SIZE;
                for (size_t i = 0; i < p->len; i++)
                    p->data[i] = (uint8_t)rnd(&seed, 256);
                p->data[0] = att_ops[rnd(&seed, (uint32_t)(sizeof(att_ops) / sizeof(att_ops[0])))];
            }
            break;
        }
    }

    return serialize_input(&in, Data, MaxSize);
}

extern size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                        const uint8_t *Data2, size_t Size2,
                                        uint8_t *Out, size_t MaxOutSize,
                                        unsigned Seed)
{
    Input a;
    Input b;
    Input out;

    uint32_t seed = Seed ? Seed : 1;

    parse_input(Data1, Size1, &a);
    parse_input(Data2, Size2, &b);

    memset(&out, 0, sizeof(out));
    out.has_mode = 1;
    out.mode = chance(&seed, 2) ? a.mode : b.mode;

    size_t max_iters = a.count + b.count + 8;
    if (max_iters > MAX_PACKETS)
        max_iters = MAX_PACKETS;

    for (size_t i = 0; i < max_iters && out.count < MAX_PACKETS; i++) {
        if (chance(&seed, 2)) {
            if (a.count)
                out.packets[out.count++] = a.packets[rnd(&seed, (uint32_t)a.count)];
        } else {
            if (b.count)
                out.packets[out.count++] = b.packets[rnd(&seed, (uint32_t)b.count)];
        }

        if (chance(&seed, 8))
            break;
    }

    if (out.count == 0) {
        out.count = 1;
        gen_att_pdu(&out.packets[0], &seed);
    }

    // Mutate a little after crossover so it is not just copying.
    if (out.count && chance(&seed, 2)) {
        Packet *p = &out.packets[rnd(&seed, (uint32_t)out.count)];
        mutate_packet_bytes(p, &seed);
    }

    return serialize_input(&out, Out, MaxOutSize);
}

#ifdef MUT_TESTING

static void dump_hex(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

int main(void)
{
    uint8_t a[8192];
    uint8_t b[8192];
    uint8_t out[8192];

    for (int i = 0; i < 10000; i++) {
        size_t as = (size_t)(rand() % sizeof(a));
        size_t bs = (size_t)(rand() % sizeof(b));

        for (size_t j = 0; j < as; j++)
            a[j] = (uint8_t)rand();

        for (size_t j = 0; j < bs; j++)
            b[j] = (uint8_t)rand();

        size_t ns = LLVMFuzzerCustomMutator(a, as, sizeof(a), (unsigned)rand());
        if (ns > sizeof(a)) {
            fprintf(stderr, "mutator overflow\n");
            return 1;
        }

        size_t cs = LLVMFuzzerCustomCrossOver(a, ns, b, bs, out, sizeof(out), (unsigned)rand());
        if (cs > sizeof(out)) {
            fprintf(stderr, "crossover overflow\n");
            return 1;
        }

        if (i < 3) {
            printf("sample mutated size=%zu: ", ns);
            dump_hex(a, ns < 64 ? ns : 64);

            printf("sample crossover size=%zu: ", cs);
            dump_hex(out, cs < 64 ? cs : 64);
        }
    }

    printf("OK\n");
    return 0;
}

#endif