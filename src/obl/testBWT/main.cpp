#include "obl/primitives.h"
#include "subtol_config.h"

#include <cstring>

#include "unistd.h"
#include <math.h>

#include <stdio.h>
#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <ctime>
#include <chrono>

#include <openssl/evp.h>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <memory>

#include <cstdint>
#include "obl/rec.h"
#include "obl/circuit.h"
#include "obl/path.h"
#include "obl/so_path.h"
#include "obl/so_circuit.h"
#include "obl/rec_parallel.h"
#include "obl/rec_standard.h"
#include "obl/primitives.h"

#include "obl/taostore_circuit_1_p.h"
#include "obl/taostore_circuit_2_p.h"
#include "obl/taostore_p.h"
#include "obl/mose.h"
#include "obl/taostore_factory.hpp"

#include <wolfcrypt/pbkdf.h>
#define bench_size (1 << 18)
#define RUN 16

using hres = std::chrono::high_resolution_clock;
using _nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, _nano>;

struct buffer
{
    std::uint8_t _buffer[8];

    bool operator==(const buffer &rhs) const
    {
        return !memcmp(_buffer, rhs._buffer, sizeof(_buffer));
    }
};

struct work_args
{
    obl::recursive_oram *rram;
    std::vector<buffer> *_mirror_data;
    unsigned int run;
    unsigned int i;
    int64_t *res_time;
};

struct queryargs
{
    size_t len;
    uint8_t *query;
};

void get_file_size(void *fb, size_t *size)
{
    fseek((FILE *)fb, 0, SEEK_END);
    *size = ftell((FILE *)fb);
}

void get_blob(void *fb, uint8_t *out, size_t len, size_t offset)
{
    if (offset != -1)
        fseek((FILE *)fb, offset, SEEK_SET);

    fread(out, sizeof(uint8_t), len, (FILE *)fb);
}

struct subtol_context_t
{
    void *fb;
    std::size_t N;
    unsigned int alpha;
    std::uint32_t *C;
    obl::oram_factory *allocator;
    // IppsAES_GCMState *cc;
    EVP_CIPHER_CTX *cc;

    obl::recursive_oram *suffix_array;
    unsigned int sa_bundle_size;
    unsigned int sa_total_blocks;
    std::uint32_t current_start_index;

    subtol_context_t(void *fb, size_t N, unsigned int alpha, obl::oram_factory *allocator, EVP_CIPHER_CTX *cc)
    {
        this->fb = fb;
        this->N = N;
        this->alpha = alpha;
        this->allocator = allocator;
        this->cc = cc;

        suffix_array = nullptr;
        C = nullptr;

        current_start_index = 0;
    }

    virtual ~subtol_context_t()
    {
        delete allocator;

        if (cc != nullptr)
        {
            EVP_CIPHER_CTX_free(cc);
        }

        if (C != nullptr)
            delete[] C;

        if (suffix_array != nullptr)
            delete suffix_array;
    }

    void load_sa(unsigned int csize, unsigned int sa_block);
    void fetch_sa(std::int32_t *sa_chunk);

    bool verify_mac(std::uint8_t *mac)
    {
        bool check;
        // uint8_t final_mac[16];
        // ippsAES_GCMGetTag(final_mac, 16, cc);
        check = EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_GCM_SET_TAG, 16, mac);
        fb = nullptr;

        EVP_CIPHER_CTX_free(cc);
        cc = nullptr;

        return check;
    }

    // virtual methods
    virtual void init() = 0;
    virtual void load_index(std::size_t buffer_size) = 0;

    // put the sauce here!!!
    virtual void query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end) = 0;
};

static const int buffer_size = 512;

void subtol_context_t::load_sa(unsigned int csize, unsigned int sa_block)
{
    int len;
    std::int32_t idx;
    std::size_t rec_oram_block_size = sa_block * sizeof(std::int32_t);
    std::size_t rec_oram_blocks = (N + 1) / sa_block + ((N + 1) % sa_block ? 1 : 0);

    std::int32_t *enc_buff = new std::int32_t[sa_block * buffer_size];
    std::int32_t *dec_buff = new std::int32_t[sa_block];

    if (allocator->is_taostore())
        suffix_array = new obl::recursive_parallel(rec_oram_blocks, rec_oram_block_size, csize, allocator);
    else
        suffix_array = new obl::recursive_oram_standard(rec_oram_blocks, rec_oram_block_size, csize, allocator);

    sa_bundle_size = sa_block;
    sa_total_blocks = rec_oram_blocks;
    current_start_index = 0;

    // all but last and possibly incomplete block
    --rec_oram_blocks;
    idx = 0;

    while (rec_oram_blocks != 0)
    {
        std::size_t curr_blocks = rec_oram_blocks > buffer_size ? buffer_size : rec_oram_blocks;

        get_blob(fb, (std::uint8_t *)enc_buff, curr_blocks * rec_oram_block_size, -1);

        for (unsigned int i = 0; i < curr_blocks; i++)
        {
            // ippsAES_GCMDecrypt((std::uint8_t *)&enc_buff[i * sa_block], (std::uint8_t *)dec_buff, rec_oram_block_size, cc);
            EVP_DecryptUpdate(cc, (std::uint8_t *)dec_buff, &len, (std::uint8_t *)&enc_buff[i * sa_block], rec_oram_block_size);
            suffix_array->access(idx, (std::uint8_t *)dec_buff, (std::uint8_t *)enc_buff); // enc_buff is a placeholder!
            ++idx;
        }

        rec_oram_blocks -= curr_blocks;
    }

    // manage remainder
    std::size_t rem = (N + 1) % sa_block;
    // if rem == 0, I discarded a full block
    if (rem == 0)
        rem = sa_block;

    get_blob(fb, (std::uint8_t *)enc_buff, rem * sizeof(std::int32_t), -1);
    // ippsAES_GCMDecrypt((std::uint8_t *)enc_buff, (std::uint8_t *)dec_buff, rem * sizeof(std::int32_t), cc);
    EVP_DecryptUpdate(cc, (std::uint8_t *)dec_buff, &len, (std::uint8_t *)enc_buff, rem * sizeof(std::int32_t));
    suffix_array->access(idx, (std::uint8_t *)dec_buff, (std::uint8_t *)enc_buff); // enc_buff is a placeholder!

    delete[] enc_buff;
    delete[] dec_buff;
}

void subtol_context_t::fetch_sa(std::int32_t *sa_chunk)
{
    if (suffix_array != nullptr)
    {
        obl::block_id sa_bid = (current_start_index / sa_bundle_size) % sa_total_blocks;
        current_start_index += sa_bundle_size;
        suffix_array->access(sa_bid, nullptr, (std::uint8_t *)sa_chunk);
    }
}

struct user_session_t
{
    subtol_config_t cfg;
    std::unique_ptr<subtol_context_t> ctx;
    int status;
    bool busy; // if true, a pending operation is in execution

    user_session_t()
    {
        status = 1;
        busy = false;
    }

    ~user_session_t() {}

    user_session_t(const user_session_t &) = delete;
    user_session_t &operator=(const user_session_t &) = delete;

    user_session_t(user_session_t &&o)
    {
        cfg = o.cfg;
        status = o.status;
        busy = o.busy;
        ctx = std::move(o.ctx);

        o.status = 1;
        o.busy = false;
    }

    user_session_t &operator=(user_session_t &&o)
    {
        cfg = o.cfg;
        status = o.status;
        busy = o.busy;
        ctx = std::move(o.ctx);

        o.status = 1;
        o.busy = false;

        return *this;
    }
};

template <typename Int>
inline Int linear_scan(Int *v, Int idx, Int limit)
{
    Int ret = -1;

    for (Int i = 0; i <= limit; i++)
        ret = obl::ternary_op(i == idx, v[i], ret);

    return ret;
}

inline std::size_t fill_with_ones(std::size_t v)
{
    // on x86-64, sizeof(std::size_t) = 8
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;

    return v;
}

inline std::size_t get_subroot(std::size_t N)
{
    std::size_t NN = fill_with_ones(N + 1);
    std::size_t rem = N - (NN >> 1);
    std::size_t max_left_subtree = (NN ^ (NN >> 1)) >> 1;
    std::size_t offset = obl::ternary_op(rem > max_left_subtree, max_left_subtree, rem);

    return (NN >> 2) + offset;
}

// Static functions

static int partial_rank(std::uint16_t *ch, int limit, int sample_rate, std::int16_t target, int enc_bit)
{
    int p_rank = 0;

    int hword = 0;
    int shift_right = 0;
    std::uint16_t mask = (1 << enc_bit) - 1;

    for (int i = 0; i < sample_rate; i++)
    {
        std::uint16_t current = (ch[hword] >> shift_right) & mask;

        shift_right += enc_bit;
        if (shift_right > 16) // this is a known, public parameter, so you don't need to hide this if
        {
            ++hword;
            shift_right -= 16;
            current = current | (ch[hword] << (enc_bit - shift_right));
            current = current & mask;
        }

        p_rank += obl::ternary_op((current == target) & (i < limit), 1, 0);
    }

    return p_rank;
}

// Implementation

template <typename Int, typename Char>
void vbwt_query(obl::recursive_oram *index, Int *C,
                Int s_rate, std::size_t s_size, std::uint64_t enc_bit, Int alpha,
                Char *q, Int qlen,
                Int *s, Int *e)
{
    Int start, end;
    std::uint8_t buffer[s_size];

    --qlen;

    start = linear_scan<Int>(C, (Int)q[qlen], alpha);
    end = linear_scan<Int>(C, (Int)q[qlen] + 1, alpha) - 1;
    --qlen;

    while (qlen != -1)
    {
        // base offset
        Int char_index = (Int)q[qlen];
        Int base_offset = linear_scan<Int>(C, char_index, alpha);

        // process start
        Int inner_offset = start % s_rate;
        Int outer_offset = start / s_rate;

        index->access(outer_offset, nullptr, buffer);

        Int *acc = (Int *)buffer;
        Int sample_offset = linear_scan<Int>(acc, char_index, alpha - 1);

        std::uint16_t *ch = (std::uint16_t *)(acc + alpha);
        Int next_start = base_offset + sample_offset + partial_rank(ch, inner_offset, s_rate, char_index, enc_bit);

        // process end
        inner_offset = (end % s_rate) + 1;
        outer_offset = end / s_rate;

        index->access(outer_offset, nullptr, buffer);

        acc = (Int *)buffer;
        sample_offset = linear_scan<Int>(acc, char_index, alpha - 1);

        ch = (std::uint16_t *)(acc + alpha);
        Int next_end = base_offset + sample_offset + partial_rank(ch, inner_offset, s_rate, char_index, enc_bit) - 1;

        // support for dummy characters
        bool dummy_char = (char_index < 0) | (char_index >= alpha);
        start = obl::ternary_op(dummy_char, start, next_start);
        end = obl::ternary_op(dummy_char, end, next_end);

        --qlen;
    }

    *s = start;
    *e = end;
}

struct bwt_context_t : public subtol_context_t
{
    unsigned int csize;
    obl::recursive_oram *index;

    std::uint64_t sample_rate;
    std::uint64_t no_bits;
    std::uint64_t sample_size;

    bwt_context_t(void *fb, size_t N, unsigned int alpha, obl::oram_factory *allocator, EVP_CIPHER_CTX *cc, unsigned int csize) : subtol_context_t(fb, N, alpha, allocator, cc)
    {
        this->csize = csize;
        index = nullptr;
    }

    void init();
    void load_meta();
    void load_c();
    void load_index(std::size_t buffer_size);

    void query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end);

    ~bwt_context_t()
    {
        if (index != nullptr)
            delete index;
    }
};

void bwt_context_t::init()
{
    load_meta();
    load_c();
    load_index(8);
}

void bwt_context_t::load_meta()
{
    int len;
    std::uint64_t meta[3];
    get_blob(fb, (std::uint8_t *)meta, 3 * sizeof(std::uint64_t), -1);
    // ippsAES_GCMProcessAAD((std::uint8_t*) meta, 3 * sizeof(std::uint64_t), cc);
    EVP_DecryptUpdate(cc, NULL, &len, (std::uint8_t *)meta, 3 * sizeof(std::uint64_t));
    sample_rate = meta[0];
    no_bits = meta[1];
    sample_size = meta[2];
}

void bwt_context_t::load_c()
{
    int len;
    C = new std::uint32_t[alpha + 1];
    std::uint32_t *C_enc = new std::uint32_t[alpha + 1];

    get_blob(fb, (std::uint8_t *)C_enc, sizeof(std::int32_t) * (alpha + 1), -1);
    // ippsAES_GCMDecrypt((std::uint8_t*) C_enc, (std::uint8_t*) C, sizeof(std::int32_t) * (alpha + 1), cc);
    EVP_DecryptUpdate(cc, (std::uint8_t *)C, &len, (std::uint8_t *)C_enc, sizeof(std::int32_t) * (alpha + 1));

    delete[] C_enc;
}

void bwt_context_t::load_index(std::size_t buffer_size)
{
    int len;
    std::uint8_t *enc_buff = new std::uint8_t[buffer_size * sample_size];
    std::uint8_t *dec_buff = new std::uint8_t[buffer_size * sample_size];

    std::size_t no_samples = (N + 1) / sample_rate + ((N + 1) % sample_rate == 0 ? 0 : 1);

    printf("numbero blocchi: %ld, dimensione blocchi %ld\n",no_samples, sample_size );
    obl::block_id idx = 0;

    if (allocator->is_taostore())
        index = new obl::recursive_parallel(no_samples, sample_size, csize, allocator);
    else
        index = new obl::recursive_oram_standard(no_samples, sample_size, csize, allocator);

    while (no_samples != 0)
    {
        std::size_t fetch_size = no_samples > buffer_size ? buffer_size : no_samples;
        std::size_t fetch_size_bytes = fetch_size * sample_size;

        get_blob(fb, enc_buff, fetch_size_bytes, -1);
        // ippsAES_GCMDecrypt(enc_buff, dec_buff, fetch_size_bytes, cc);
        EVP_DecryptUpdate(cc, dec_buff, &len, enc_buff, fetch_size_bytes);

        std::uint8_t *current_sample = dec_buff;

        for (unsigned int i = 0; i < fetch_size; i++)
        {
            // enc_buf is a real placeholder
            index->access(idx, current_sample, enc_buff);
            current_sample += sample_size;
            ++idx;
        }

        no_samples -= fetch_size;
    }

    delete[] enc_buff;
    delete[] dec_buff;
}

void bwt_context_t::query(unsigned char *q, std::size_t len, std::uint32_t &start, std::uint32_t &end)
{
    vbwt_query<std::uint32_t, unsigned char>(index, C, sample_rate, sample_size, no_bits, alpha, q, len, &start, &end);
}

user_session_t session;

static int obl_strlen(char *pwd)
{
    /* 
		64 is the max size of a subtol passphrase.
		This is pretty dummy actually:
		- scan 64 bytes
		- for each 0x00 increase zeroes
		- return 64-zeroes
		
		Assume that the passphrase is a C-string padded with 0s at the end
	*/
    int zeroes = 0;

    for (int i = 0; i < 64; i++)
        zeroes += (pwd[i] == 0x00);

    return 64 - zeroes;
}

subtol_context_t *init_subtol_context(void *fb, char *pwd, subtol_config_t &cfg)
{
    size_t filesize;
    uint8_t aes_key[16];
    // AES-GCM material
    uint8_t iv[12];
    uint8_t mac[16];
    uint8_t *salt;
    // IppsAES_GCMState *cc;
    EVP_CIPHER_CTX *ctx;
    int len;

    int gcm_state_size;
    // header
    bool has_sa;
    uint64_t algorithm_selection, algo;
    uint64_t header[4];

    // fb is a void* pointer, that is meant to point to a FILE*
    // since enclaves don't allow direct use of syscalls, some I/O structs are left unimplemented in the sgx_tlibc
    // we don't need to check where that pointer belongs since it will just be handled to untrusted code to perform
    // file operations

    // get MAC
    get_file_size(fb, &filesize);
    get_blob(fb, mac, 16, filesize - 16);

    // get headers
    get_blob(fb, (uint8_t *)&algorithm_selection, sizeof(uint64_t), 0);
    has_sa = algorithm_selection >= 4;
    algo = algorithm_selection % 4;

    get_blob(fb, (uint8_t *)header, 4 * sizeof(uint64_t), -1);
    // for now only 4-bytes integers are supported
    assert(header[2] == sizeof(int32_t));

    // get aes-gcm IV which is suggested to be 12-bytes in size
    get_blob(fb, iv, 12, -1);
    // dump the salt
    salt = new uint8_t[header[3]];
    get_blob(fb, salt, header[3], -1);
    wc_PBKDF2(aes_key, (unsigned char *)pwd, obl_strlen(pwd), salt, header[3], 16384, 16, WC_HASH_TYPE_SHA256);
    std::memset(pwd, 0x00, 64);

    // initialize crypto stuff and authenticate unencrypted data
    // taken from sgx_tcrypto sdk code

    // ippsAES_GCMGetSize(&gcm_state_size);
    // cc = (IppsAES_GCMState *)malloc(gcm_state_size);
    ctx = EVP_CIPHER_CTX_new();

    // ippsAES_GCMInit(aes_key, 16, cc, gcm_state_size);
    // std::memset(aes_key, 0x00, 16);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv);

    // ippsAES_GCMReset(cc);
    // ippsAES_GCMProcessIV(iv, 12, cc);

    // authenticate unencrypted data
    // ippsAES_GCMProcessAAD((uint8_t *)&algorithm_selection, sizeof(uint64_t), cc);
    EVP_DecryptUpdate(ctx, NULL, &len, (uint8_t *)&algorithm_selection, sizeof(uint64_t));

    // ippsAES_GCMProcessAAD((uint8_t *)header, sizeof(uint64_t) * 4, cc);
    EVP_DecryptUpdate(ctx, NULL, &len, (uint8_t *)header, sizeof(uint64_t) * 4);

    // ippsAES_GCMProcessAAD(iv, 12, cc);
    EVP_DecryptUpdate(ctx, NULL, &len, iv, 12);

    // ippsAES_GCMProcessAAD(salt, header[3], cc);
    EVP_DecryptUpdate(ctx, NULL, &len, salt, header[3]);

    delete[] salt;

    // UP TO HERE SUBTOL PREPARATION IS EXACTLY THE SAME!
    // NOW DIFFERENTIATE ACCORDING TO THE ALGORITHM

    // create ORAM allocator
    bool invalid = false;
    obl::oram_factory *allocator = nullptr;

    switch (cfg.base_oram)
    {
    case OBL_CIRCUIT_ORAM:
        allocator = new obl::coram_factory(cfg.Z, cfg.stash_size);
        break;

    case OBL_PATH_ORAM:
        allocator = new obl::path_factory(cfg.Z, cfg.stash_size, cfg.A);
        break;

    case CIRCUIT_ORAM:
        allocator = new obl::so_coram_factory(cfg.Z, cfg.stash_size);
        break;

    case PATH_ORAM:
        allocator = new obl::so_path_factory(cfg.Z, cfg.stash_size);
        break;
    case SHADOW_DORAM_V1:
        allocator = new obl::taostore_circuit_1_parallel_factory(cfg.Z, cfg.stash_size, cfg.tnum);
        break;
    case SHADOW_DORAM_V2:
        allocator = new obl::taostore_circuit_2_parallel_factory(cfg.Z, cfg.stash_size, cfg.tnum);
        break;
    case ASYNCH_DORAM:
        allocator = new obl::taostore_circuit_factory(cfg.Z, cfg.stash_size, cfg.tnum);
        break;
    case MOSE:
        allocator = new obl::mose_factory(cfg.Z, cfg.stash_size, cfg.tnum);
        break;
    case ASYNCHMOSE:
        allocator = new obl::asynch_mose_factory(cfg.Z, cfg.stash_size, cfg.tnum);
        break;
    default:
        invalid = true;
    }
    // create subtol context
    subtol_context_t *session = nullptr;

    switch (algo)
    {
    case 2: // SUBTOL_VBWT
        session = new bwt_context_t(fb, header[0], header[1], allocator, ctx, cfg.csize);
        break;

    default:
        invalid = true;
    }

    if (!invalid)
    {
        if (has_sa)
        {
            session->load_sa(cfg.csize, cfg.sa_block);
        }

        session->init();

        bool success = session->verify_mac(mac);

        if (!success)
        {
            delete session;
            session = nullptr;
        }
    }

    return session;

    // deallocated by subtol_context
    //delete allocator;
    //free(cc);
}

void create_session()
{
    // create a fresh context
    user_session_t clean_session;

    session = std::move(clean_session);
}

void configure(std::uint8_t *cfg)
{
    std::uint32_t *cfg32 = (std::uint32_t *)cfg;

    session.cfg.base_oram = (obl_oram_t)cfg32[0];
    session.cfg.Z = cfg32[1];
    session.cfg.stash_size = cfg32[2];
    session.cfg.S = cfg32[3];
    session.cfg.A = cfg32[4];
    session.cfg.csize = cfg32[5];
    session.cfg.sa_block = cfg32[6];
    session.cfg.tnum = cfg32[7];
    session.status = 2;
}

void loader(void *fp)
{
    // passphrase is a AES-GCM string held in a buffer of at most 64-bytes
    std::uint8_t dec_passphrase[64] = "ciaone";

    // dump required stuff
    subtol_config_t cfg = session.cfg;
    subtol_context_t *context = init_subtol_context(fp, (char *)dec_passphrase, cfg);

    session.ctx = std::unique_ptr<subtol_context_t>(context);
    session.status = 3;
}

void query(uint8_t *q, size_t len, int32_t *res)
{
    unsigned char *qq = new unsigned char[len];

    std::memcpy((std::uint8_t *)qq, q, len);

    std::uint32_t tmp_res[2];
    session.ctx->query(qq, len, tmp_res[0], tmp_res[1]);
    // this is to later fetch suffix-array entries
    session.ctx->current_start_index = obl::ternary_op((tmp_res[0] != -1) & (tmp_res[0] <= tmp_res[1]), tmp_res[0], 0);

    std::memset(qq, 0x00, len);
    std::memcpy((std::uint8_t *)res, tmp_res, 2 * sizeof(std::int32_t));
}

void *workerquery(void *args)
{
    std::int32_t res[4];
    std::int64_t *res64 = (std::int64_t *)res;
    size_t len = ((queryargs *)args)->len;

    query(((queryargs *)args)->query, len, res);
    return nullptr;
}

int main(int argc, char *argv[])
{
    pthread_t workers[RUN];
    FILE *fp;

    if (argc < 3)
    {
        printf("error arguments too few");
        return 0;
    }
    char *filename = argv[1];

    int oram = atoi(argv[2]);
    int csize = atoi(argv[3]);
    int tnum = atoi(argv[4]);
    tt start, end;
    _nano diff;
    // char *filename = new char[payload_size - 64 + 1];
    // std::memcpy(filename, &payload[64], payload_size - 64);
    // filename[payload_size - 64] = '\0';

    create_session();

    std::uint32_t *cfg = new std::uint32_t[8];

    cfg[0] = oram;
    cfg[1] = 3; //Z
    cfg[2] = 8; //S

    cfg[3] = 0;
    cfg[4] = 0; //A

    cfg[5] = csize;
    cfg[6] = 16;
    cfg[7] = tnum;

    configure((std::uint8_t *)cfg);

    fp = fopen(filename, "rb");

    if (fp != NULL)
    {
        loader(fp);
        fclose(fp);
    }

    // When forty winters shall besiege thy brow
    unsigned char *qq;
    size_t len;
    // res[0] and res[1] keep start and end
    // res[2] and res[3] make 64-bit for time
    std::int32_t res[4];
    std::int64_t *res64 = (std::int64_t *)res;

    queryargs tmp;
    for (int i = 5; i < argc; i++)
    {
        if (strncmp(argv[1], "4G_human_", 8) == 0)
        {
            for (int T = 1; T <= RUN; T *= 2)
            {
                tmp.len = strlen((char *)argv[i]);
                tmp.query = new uint8_t[tmp.len];
                for (int j = 0; j < tmp.len; j++)
                    tmp.query[i] = (uint8_t) argv[i][j] - (uint8_t)1;

                start = hres::now();
                for (int j = 0; j < T; j++)
                    pthread_create(&workers[j], nullptr, workerquery, (void *)&tmp);
                for (int j = 0; j < T; j++)
                    pthread_join(workers[j], nullptr);
                end = hres::now();
                diff = end - start;

                std::cout << cfg[0] << "," << T << "," << diff.count() << std::endl;
            }
        }
        else
        {

            for (int T = 1; T <= RUN; T *= 2)
            {
                tmp.len = strlen((char *)argv[i]);
                tmp.query = new uint8_t[tmp.len];
                memcpy(tmp.query, (uint8_t *)argv[i], tmp.len);
                start = hres::now();
                for (int j = 0; j < T; j++)
                    pthread_create(&workers[j], nullptr, workerquery, (void *)&tmp);
                for (int j = 0; j < T; j++)
                    pthread_join(workers[j], nullptr);
                end = hres::now();
                diff = end - start;

                std::cout << cfg[0] << "," << T << "," << diff.count() << std::endl;

                // qq = new unsigned char [len];
                // memcpy(qq, argv[i+1], len);

                // start = hres::now();
                // query((uint8_t *)argv[i], len, res);
                // end = hres::now();

                // diff = end - start;
                // res64[1] = diff.count();

                // std::cout << "start: " << res[0] << ", end: " << res[1] << ", time :" << res64[1] << std::endl;

                // std::size_t payload_size = session.ctx->sa_bundle_size;
                // std::int32_t buff[session.ctx->sa_bundle_size];

                // start = hres::now();
                // session.ctx->fetch_sa(buff);
                // end = hres::now();
                // diff = end - start;

                // res64[1] = diff.count();

                // std::cout << "SA time :" << res64[1] << "bundle size" << session.ctx->sa_bundle_size << std::endl;
            }
        }
    }
}