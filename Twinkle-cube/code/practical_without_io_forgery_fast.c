#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define STATE_BITS 1280
#define STATE_WORDS 20
#define LANE_SIZE 80
#define X_SIZE 4
#define Y_SIZE 4
#define MAX_TAG_BITS 1152
#define MAX_TAG_WORDS 18

static const int O0[16] = {20,24,38,77,49,66,30,40,76,15,46,50,17,18,61,62};
static const int O1[16] = {63,45,34,39,32,43,60,66,54,26,55,36,61,12,15,35};

static const char *ROUND_CONSTANTS[5] = {
    "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e638d01377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b54709179216d5d98979fb1bd1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96ba7c9045f12c7f9924a19947b3916cf70801f2e2858efc16636920d871574e69a458fea3f4933d7e0d95748f728eb658718bcd5882154aee7b54a41dc25a59b5",
    "9c30d5392af26013c5d1b023286085f0ca417918b8db38ef8e79dcb0603a180e6c9e0e8bb01e8a3ed71577c1bd314b2778af2fda55605c60e65525f3aa55ab945748986263e8144055ca396a2aab10b6b4cc5c341141e8cea15486af7c72e993b3ee1411636fbc2a2ba9c55d741831f6ce5c3e169b87931eafd6ba336c24cf5c7a325381289586773b8f48986b4bb9afc4bfe81b6628219361d809ccfb21a991",
    "487cac605dec8032ef845d5de98575b1dc262302eb651b8823893e81d396acc50f6d6ff383f442392e0b4482a484200469c8f04a9e1f9b5e21c66842f6e96c9a670c9c61abd388f06a51a0d2d8542f68960fa728ab5133a36eef0b6c137a3be4ba3bf0507efb2a98a1f1651d39af017666ca593e82430e888cee8619456f9fb47d84a5c33b8b5ebee06f75d885c12073401a449f56c16aa64ed3aa62363f7706",
    "1bfedf72429b023d37d0d724d00a1248db0fead349f1c09b075372c980991b7b25d479d8f6e8def7e3fe501ab6794c3b976ce0bd04c006bac1a94fb6409f60c45e5c9ec2196a246368fb6faf3e6c53b51339b2eb3b52ec6f6dfc511f9b30952ccc814544af5ebd09bee3d004de334afd660f2807192e4bb3c0cba85745c8740fd20b5f39b9d3fbdb5579c0bd1a60320ad6a100c6402c7279679f25fefb1fa3cc",
    "8ea5e9f8db3222f83c7516dffd616b152f501ec8ad0552ab323db5fafd23876053317b483e00df829e5c57bbca6f8ca01a87562edf1769dbd542a8f6287effc3ac6732c68c4f5573695b27b0bbca58c8e1ffa35db8f011a010fa3d98fd2183b84afcb56c2dd1d35b9a53e479b6f84565d28e49bc4bfb9790e1ddf2daa4cb7e3362fb1341cee4c6e8ef20cada36774c01d07e9efe2bf11fb495dbda4dae909198"
};

static inline int index_xyz(int x, int y, int z) { return x + 4*y + 16*z; }
static inline int index_xy(int x, int y) { return x + 4*y; }
static inline int get_bit_words(const uint64_t words[], int i) { return (int)((words[i >> 6] >> (i & 63)) & 1ULL); }
static inline void set_bit_words(uint64_t words[], int i, int bit) {
    uint64_t mask = 1ULL << (i & 63);
    if (bit) words[i >> 6] |= mask; else words[i >> 6] &= ~mask;
}
static inline void xor_bit_words(uint64_t words[], int i, int bit) {
    if (bit) words[i >> 6] ^= (1ULL << (i & 63));
}

static int parse_bit_string(const char *s, int expected_bits, uint64_t out[]) {
    size_t n = strlen(s);
    int words = (expected_bits + 63) / 64;
    for (int i = 0; i < words; i++) out[i] = 0;
    if ((int)n != expected_bits) return 0;
    for (int i = 0; i < expected_bits; i++) {
        if (s[i] == '1') set_bit_words(out, i, 1);
        else if (s[i] != '0') return 0;
    }
    return 1;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void xor_round_constant(uint64_t state[], int round) {
    const char *hex = ROUND_CONSTANTS[round];
    size_t len = strlen(hex);
    for (int pos = 0; pos < STATE_BITS; pos++) {
        int hex_pos_from_right = pos / 4;
        if ((size_t)hex_pos_from_right >= len) break;
        int nib = hex_nibble(hex[len - 1 - (size_t)hex_pos_from_right]);
        int bit = (nib >> (pos & 3)) & 1;
        xor_bit_words(state, pos, bit);
    }
}

static void sbox_step(const uint64_t in[STATE_WORDS], uint64_t out[STATE_WORDS]) {
    for (int i = 0; i < STATE_WORDS; i++) out[i] = 0;
    for (int y = 0; y < Y_SIZE; y++) for (int z = 0; z < LANE_SIZE; z++) {
        int p0=index_xyz(0,y,z), p1=index_xyz(1,y,z), p2=index_xyz(2,y,z), p3=index_xyz(3,y,z);
        int i0=get_bit_words(in,p0), i1=get_bit_words(in,p1), i2=get_bit_words(in,p2), i3=get_bit_words(in,p3);
        int o0=(i0&i2&i3)^(i0&i3)^i0^(i1&i2)^(i1&i3)^(i2&i3);
        int o1=(i0&i1)^(i0&i3)^i1^i2;
        int o2=(i0&i1&i2)^i0^(i1&i3)^i1^(i2&i3)^i3;
        int o3=i0^(i1&i2)^(i2&i3)^i2^i3;
        set_bit_words(out,p0,o0); set_bit_words(out,p1,o1); set_bit_words(out,p2,o2); set_bit_words(out,p3,o3);
    }
}

static void lane_rotation(const uint64_t in[STATE_WORDS], uint64_t out[STATE_WORDS], const int offsets[16]) {
    for (int i = 0; i < STATE_WORDS; i++) out[i] = in[i];
    for (int y = 0; y < Y_SIZE; y++) for (int x = 0; x < X_SIZE; x++) {
        int shift = offsets[index_xy(x,y)] % LANE_SIZE;
        for (int z = 0; z < LANE_SIZE; z++) {
            int bit = get_bit_words(in, index_xyz(x,y,(z + shift) % LANE_SIZE));
            set_bit_words(out, index_xyz(x,y,z), bit);
        }
    }
}

static void mix_slice(const uint64_t in[STATE_WORDS], uint64_t out[STATE_WORDS]) {
    for (int i = 0; i < STATE_WORDS; i++) out[i] = 0;
    for (int z = 0; z < LANE_SIZE; z++) {
        int base = 16*z;
        for (int i = 0; i < 16; i++) {
            int bit = get_bit_words(in, base+i) ^ get_bit_words(in, base+((i-5+16)&15)) ^ get_bit_words(in, base+((i-12+16)&15));
            set_bit_words(out, base+i, bit);
        }
    }
}

static void twinkle_tag(const uint64_t pointer[STATE_WORDS], const uint64_t key[STATE_WORDS], int tag_len, int rounds, uint64_t tag_words[MAX_TAG_WORDS]) {
    uint64_t s[STATE_WORDS], t1[STATE_WORDS], t2[STATE_WORDS];
    for (int i = 0; i < STATE_WORDS; i++) s[i] = pointer[i] ^ key[i];
    for (int r = 0; r < rounds; r++) {
        sbox_step(s, t1);
        lane_rotation(t1, t2, O0);
        mix_slice(t2, t1);
        lane_rotation(t1, s, O1);
        xor_round_constant(s, r);
    }
    for (int i = 0; i < MAX_TAG_WORDS; i++) tag_words[i] = 0;
    for (int i = 0; i < tag_len; i++) {
        int bit = get_bit_words(s, i) ^ get_bit_words(s, (i + 128) % STATE_BITS);
        if (bit) tag_words[i >> 6] |= (1ULL << (i & 63));
    }
}

static void tag_words_to_bits(const uint64_t tag_words[MAX_TAG_WORDS], int tag_len, char *buf) {
    for (int i = 0; i < tag_len; i++) buf[i] = ((tag_words[i >> 6] >> (i & 63)) & 1ULL) ? '1' : '0';
    buf[tag_len] = '\0';
}

static int parse_cube_indices(const char *s, int idx[], int *d) {
    char *copy = (char *)malloc(strlen(s) + 1);
    if (!copy) return 0;
    strcpy(copy, s);
    int n = 0;
    char *tok = strtok(copy, ",");
    while (tok) {
        if (n >= 64) { free(copy); return 0; }
        char *end = NULL;
        long v = strtol(tok, &end, 10);
        if (*end != '\0' || v < 0 || v >= STATE_BITS) { free(copy); return 0; }
        idx[n++] = (int)v;
        tok = strtok(NULL, ",");
    }
    free(copy);
    *d = n;
    return n > 0;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s --key-bits <1280 bits> --base-pointer <1280 bits> --cube-indices <csv> --target-assignment <n> --tag-length <n> --rounds <1..5> --start <n> --count <n>\n", argv0);
}

int main(int argc, char **argv) {
    const char *key_bits = NULL, *base_bits = NULL, *cube_csv = NULL;
    uint64_t target_assignment = 0, start = 0, count = 0;
    int tag_len = 0, rounds = 5;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key-bits") == 0 && i + 1 < argc) key_bits = argv[++i];
        else if (strcmp(argv[i], "--base-pointer") == 0 && i + 1 < argc) base_bits = argv[++i];
        else if (strcmp(argv[i], "--cube-indices") == 0 && i + 1 < argc) cube_csv = argv[++i];
        else if (strcmp(argv[i], "--target-assignment") == 0 && i + 1 < argc) target_assignment = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--tag-length") == 0 && i + 1 < argc) tag_len = atoi(argv[++i]);
        else if (strcmp(argv[i], "--rounds") == 0 && i + 1 < argc) rounds = atoi(argv[++i]);
        else if (strcmp(argv[i], "--start") == 0 && i + 1 < argc) start = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = strtoull(argv[++i], NULL, 10);
        else { usage(argv[0]); return 2; }
    }
    if (!key_bits || !base_bits || !cube_csv || tag_len < 1 || tag_len > MAX_TAG_BITS || count == 0 || rounds < 1 || rounds > 5) { usage(argv[0]); return 2; }
    uint64_t key[STATE_WORDS], base[STATE_WORDS];
    if (!parse_bit_string(key_bits, STATE_BITS, key) || !parse_bit_string(base_bits, STATE_BITS, base)) {
        fprintf(stderr, "invalid bit string length/content\n"); return 2;
    }
    int cube_idx[64], d = 0;
    if (!parse_cube_indices(cube_csv, cube_idx, &d)) { fprintf(stderr, "invalid cube indices\n"); return 2; }
    uint64_t total = (d == 64) ? UINT64_MAX : (1ULL << d);
    uint64_t end = start + count;
    if (end < start || end > total) end = total;
    uint64_t xor_tag[MAX_TAG_WORDS] = {0}, processed = 0, skipped = 0;
    for (uint64_t a = start; a < end; a++) {
        if (a == target_assignment) { skipped++; continue; }
        uint64_t ptr[STATE_WORDS];
        for (int i = 0; i < STATE_WORDS; i++) ptr[i] = base[i];
        for (int j = 0; j < d; j++) set_bit_words(ptr, cube_idx[j], (int)((a >> j) & 1ULL));
        uint64_t tag[MAX_TAG_WORDS];
        twinkle_tag(ptr, key, tag_len, rounds, tag);
        for (int w = 0; w < MAX_TAG_WORDS; w++) xor_tag[w] ^= tag[w];
        processed++;
    }
    char *bits = (char *)malloc((size_t)tag_len + 1);
    if (!bits) return 3;
    tag_words_to_bits(xor_tag, tag_len, bits);
    printf("processed=%" PRIu64 "\n", processed);
    printf("skipped_target=%" PRIu64 "\n", skipped);
    printf("xor_tag_bits=%s\n", bits);
    free(bits);
    return 0;
}
