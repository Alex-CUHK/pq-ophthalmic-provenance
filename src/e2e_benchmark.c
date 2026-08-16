#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <limits.h>

enum {
    ALG_ECDSA = 0,
    ALG_MLDSA = 1
};

typedef struct {
    char *image_name;
    char *patient_id;
    char *label;
    char *quality_score;

    unsigned char *image;
    size_t image_len;

    unsigned char *expected_provenance;
    size_t expected_provenance_len;
} Record;

static uint64_t now_ns(void)
{
    struct timespec ts;

#ifdef CLOCK_MONOTONIC_RAW
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif

    return (
        (uint64_t)ts.tv_sec * 1000000000ULL
        + (uint64_t)ts.tv_nsec
    );
}

static const char *alg_name(int alg)
{
    return alg == ALG_ECDSA
        ? "ECDSA_P256_SHA256"
        : "ML_DSA_65";
}

static char *copy_string(const char *s)
{
    size_t n = strlen(s);

    char *out = malloc(n + 1);

    if (!out)
        return NULL;

    memcpy(out, s, n + 1);

    return out;
}

static void trim_newline(char *s)
{
    size_t n = strlen(s);

    while (
        n > 0 &&
        (s[n - 1] == '\n' || s[n - 1] == '\r')
    ) {
        s[n - 1] = '\0';
        n--;
    }
}

static int read_file(
    const char *path,
    unsigned char **data,
    size_t *len
)
{
    FILE *f = fopen(path, "rb");

    if (!f)
        return 0;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }

    long n = ftell(f);

    if (n < 0) {
        fclose(f);
        return 0;
    }

    rewind(f);

    unsigned char *buf =
        malloc(n > 0 ? (size_t)n : 1);

    if (!buf) {
        fclose(f);
        return 0;
    }

    size_t got =
        fread(buf, 1, (size_t)n, f);

    fclose(f);

    if (got != (size_t)n) {
        free(buf);
        return 0;
    }

    *data = buf;
    *len = got;

    return 1;
}

static EVP_PKEY *generate_key(
    int alg,
    uint64_t *elapsed_ns
)
{
    uint64_t start = now_ns();

    EVP_PKEY *key;

    if (alg == ALG_ECDSA) {

        key = EVP_PKEY_Q_keygen(
            NULL,
            NULL,
            "EC",
            "P-256"
        );

    } else {

        key = EVP_PKEY_Q_keygen(
            NULL,
            NULL,
            "ML-DSA-65"
        );
    }

    uint64_t end = now_ns();

    *elapsed_ns = end - start;

    return key;
}

static void digest_to_hex(
    const unsigned char *digest,
    size_t digest_len,
    char *hex_out
)
{
    static const char HEX[] =
        "0123456789abcdef";

    for (size_t i = 0; i < digest_len; i++) {
        hex_out[i * 2] =
            HEX[digest[i] >> 4];

        hex_out[i * 2 + 1] =
            HEX[digest[i] & 0x0f];
    }

    hex_out[digest_len * 2] = '\0';
}

static int construct_provenance(
    const Record *record,
    const char *image_sha256,
    char *buffer,
    size_t buffer_size,
    size_t *output_len
)
{
    int n = snprintf(
        buffer,
        buffer_size,

        "{\"dataset\":\"HYGD\","
        "\"dataset_version\":\"1.1.0\","
        "\"hash_algorithm\":\"SHA-256\","
        "\"image_name\":\"%s\","
        "\"image_sha256\":\"%s\","
        "\"label\":\"%s\","
        "\"patient_id\":\"%s\","
        "\"provenance_schema\":\"oph-pq-provenance-v1\","
        "\"quality_score\":\"%s\"}",

        record->image_name,
        image_sha256,
        record->label,
        record->patient_id,
        record->quality_score
    );

    if (
        n < 0 ||
        (size_t)n >= buffer_size
    ) {
        return 0;
    }

    *output_len = (size_t)n;

    return 1;
}

/*
Caller allocates:
- hash_ctx
- sign_ctx
- provenance buffer
- signature buffer

before the timed interval.
*/
static int run_e2e_one(
    int alg,
    EVP_PKEY *key,
    EVP_MD *sha256_md,
    const Record *record,
    EVP_MD_CTX *hash_ctx,
    EVP_MD_CTX *sign_ctx,
    char *prov_buffer,
    size_t prov_buffer_size,
    unsigned char *sig_buffer,
    size_t max_sig_size,

    uint64_t *hash_ns,
    uint64_t *construct_ns,
    uint64_t *sign_ns,
    uint64_t *total_ns,

    size_t *prov_len_out,
    size_t *sig_len_out
)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    char digest_hex[EVP_MAX_MD_SIZE * 2 + 1];

    uint64_t t0 = now_ns();

    if (
        EVP_DigestInit_ex2(
            hash_ctx,
            sha256_md,
            NULL
        ) != 1
    ) {
        return 0;
    }

    if (
        EVP_DigestUpdate(
            hash_ctx,
            record->image,
            record->image_len
        ) != 1
    ) {
        return 0;
    }

    if (
        EVP_DigestFinal_ex(
            hash_ctx,
            digest,
            &digest_len
        ) != 1
    ) {
        return 0;
    }

    digest_to_hex(
        digest,
        digest_len,
        digest_hex
    );

    uint64_t t1 = now_ns();

    size_t provenance_len = 0;

    if (
        !construct_provenance(
            record,
            digest_hex,
            prov_buffer,
            prov_buffer_size,
            &provenance_len
        )
    ) {
        return 0;
    }

    uint64_t t2 = now_ns();

    EVP_MD_CTX_reset(sign_ctx);

    int rc;

    if (alg == ALG_ECDSA) {

        rc = EVP_DigestSignInit_ex(
            sign_ctx,
            NULL,
            "SHA256",
            NULL,
            NULL,
            key,
            NULL
        );

    } else {

        rc = EVP_DigestSignInit_ex(
            sign_ctx,
            NULL,
            NULL,
            NULL,
            NULL,
            key,
            NULL
        );
    }

    size_t sig_len = max_sig_size;

    if (rc == 1) {

        rc = EVP_DigestSign(
            sign_ctx,
            sig_buffer,
            &sig_len,
            (unsigned char *)prov_buffer,
            provenance_len
        );
    }

    uint64_t t3 = now_ns();

    if (rc != 1)
        return 0;

    *hash_ns = t1 - t0;
    *construct_ns = t2 - t1;
    *sign_ns = t3 - t2;
    *total_ns = t3 - t0;

    *prov_len_out = provenance_len;
    *sig_len_out = sig_len;

    return 1;
}

static int make_provenance_filename(
    const char *image_name,
    char *out,
    size_t out_size
)
{
    const char *dot =
        strrchr(image_name, '.');

    size_t stem_len =
        dot
        ? (size_t)(dot - image_name)
        : strlen(image_name);

    if (
        stem_len +
        strlen(".provenance.json") +
        1 >
        out_size
    ) {
        return 0;
    }

    memcpy(out, image_name, stem_len);

    strcpy(
        out + stem_len,
        ".provenance.json"
    );

    return 1;
}

static size_t load_records(
    const char *manifest_path,
    const char *image_dir,
    const char *provenance_dir,
    Record **out_records,
    size_t requested
)
{
    FILE *f =
        fopen(manifest_path, "r");

    if (!f) {
        perror("manifest");
        return 0;
    }

    Record *records =
        calloc(requested, sizeof(Record));

    if (!records) {
        fclose(f);
        return 0;
    }

    char line[8192];

    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        free(records);
        return 0;
    }

    size_t count = 0;

    while (
        count < requested &&
        fgets(line, sizeof(line), f)
    ) {
        trim_newline(line);

        char *save = NULL;

        char *image_name =
            strtok_r(line, ",", &save);

        char *patient_id =
            strtok_r(NULL, ",", &save);

        char *label =
            strtok_r(NULL, ",", &save);

        char *quality_score =
            strtok_r(NULL, ",", &save);

        if (
            !image_name ||
            !patient_id ||
            !label ||
            !quality_score
        ) {
            break;
        }

        records[count].image_name =
            copy_string(image_name);

        records[count].patient_id =
            copy_string(patient_id);

        records[count].label =
            copy_string(label);

        records[count].quality_score =
            copy_string(quality_score);

        if (
            !records[count].image_name ||
            !records[count].patient_id ||
            !records[count].label ||
            !records[count].quality_score
        ) {
            break;
        }

        char path[PATH_MAX];

        snprintf(
            path,
            sizeof(path),
            "%s/%s",
            image_dir,
            image_name
        );

        if (
            !read_file(
                path,
                &records[count].image,
                &records[count].image_len
            )
        ) {
            fprintf(
                stderr,
                "Cannot read image: %s\n",
                path
            );

            break;
        }

        char prov_name[PATH_MAX];

        if (
            !make_provenance_filename(
                image_name,
                prov_name,
                sizeof(prov_name)
            )
        ) {
            break;
        }

        snprintf(
            path,
            sizeof(path),
            "%s/%s",
            provenance_dir,
            prov_name
        );

        if (
            !read_file(
                path,
                &records[count].expected_provenance,
                &records[count].expected_provenance_len
            )
        ) {
            fprintf(
                stderr,
                "Cannot read provenance: %s\n",
                path
            );

            break;
        }

        count++;
    }

    fclose(f);

    *out_records = records;

    return count;
}

static void free_records(
    Record *records,
    size_t count
)
{
    for (size_t i = 0; i < count; i++) {

        free(records[i].image_name);
        free(records[i].patient_id);
        free(records[i].label);
        free(records[i].quality_score);

        free(records[i].image);
        free(records[i].expected_provenance);
    }

    free(records);
}

static int preflight_canonicalization(
    Record *records,
    size_t count,
    EVP_MD *sha256_md
)
{
    EVP_MD_CTX *ctx =
        EVP_MD_CTX_new();

    if (!ctx)
        return 0;

    char prov[1024];

    for (size_t i = 0; i < count; i++) {

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;

        char hex[
            EVP_MAX_MD_SIZE * 2 + 1
        ];

        if (
            EVP_DigestInit_ex2(
                ctx,
                sha256_md,
                NULL
            ) != 1 ||
            EVP_DigestUpdate(
                ctx,
                records[i].image,
                records[i].image_len
            ) != 1 ||
            EVP_DigestFinal_ex(
                ctx,
                digest,
                &digest_len
            ) != 1
        ) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }

        digest_to_hex(
            digest,
            digest_len,
            hex
        );

        size_t prov_len = 0;

        if (
            !construct_provenance(
                &records[i],
                hex,
                prov,
                sizeof(prov),
                &prov_len
            )
        ) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }

        if (
            prov_len !=
                records[i].expected_provenance_len
            ||
            memcmp(
                prov,
                records[i].expected_provenance,
                prov_len
            ) != 0
        ) {
            fprintf(
                stderr,
                "Canonical mismatch: %s\n",
                records[i].image_name
            );

            EVP_MD_CTX_free(ctx);

            return 0;
        }
    }

    EVP_MD_CTX_free(ctx);

    return 1;
}

/* deterministic SplitMix64 */
static uint64_t rng_state;

static uint64_t rng_next(void)
{
    uint64_t z =
        (rng_state +=
         0x9e3779b97f4a7c15ULL);

    z =
        (z ^ (z >> 30))
        * 0xbf58476d1ce4e5b9ULL;

    z =
        (z ^ (z >> 27))
        * 0x94d049bb133111ebULL;

    return z ^ (z >> 31);
}

static void build_schedule(
    int *first_alg,
    int blocks,
    uint64_t seed
)
{
    int half = blocks / 2;

    for (int i = 0; i < blocks; i++) {
        first_alg[i] =
            i < half
            ? ALG_ECDSA
            : ALG_MLDSA;
    }

    rng_state = seed;

    for (int i = blocks - 1; i > 0; i--) {

        int j =
            (int)(
                rng_next()
                % (uint64_t)(i + 1)
            );

        int tmp = first_alg[i];

        first_alg[i] = first_alg[j];
        first_alg[j] = tmp;
    }
}

static int run_algorithm_block(
    const char *run_name,
    int block,
    int position,
    int alg,
    Record *records,
    size_t count,
    EVP_MD *sha256_md,
    FILE *timings,
    FILE *keygen
)
{
    uint64_t keygen_ns = 0;

    EVP_PKEY *key =
        generate_key(
            alg,
            &keygen_ns
        );

    int key_ok =
        key != NULL;

    fprintf(
        keygen,
        "%s,%d,%s,%d,%llu,%d\n",
        run_name,
        block,
        alg_name(alg),
        position,
        (unsigned long long)keygen_ns,
        key_ok
    );

    fflush(keygen);

    if (!key_ok) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    int max_sig =
        EVP_PKEY_get_size(key);

    if (max_sig <= 0) {
        EVP_PKEY_free(key);
        return 0;
    }

    unsigned char *sig_buffer =
        OPENSSL_malloc(
            (size_t)max_sig
        );

    char *prov_buffer =
        malloc(1024);

    EVP_MD_CTX *hash_ctx =
        EVP_MD_CTX_new();

    EVP_MD_CTX *sign_ctx =
        EVP_MD_CTX_new();

    if (
        !sig_buffer ||
        !prov_buffer ||
        !hash_ctx ||
        !sign_ctx
    ) {
        OPENSSL_free(sig_buffer);
        free(prov_buffer);
        EVP_MD_CTX_free(hash_ctx);
        EVP_MD_CTX_free(sign_ctx);
        EVP_PKEY_free(key);

        return 0;
    }

    int all_ok = 1;

    for (size_t i = 0; i < count; i++) {

        uint64_t hash_ns = 0;
        uint64_t construct_ns = 0;
        uint64_t sign_ns = 0;
        uint64_t total_ns = 0;

        size_t provenance_len = 0;
        size_t signature_len = 0;

        int ok =
            run_e2e_one(
                alg,
                key,
                sha256_md,
                &records[i],

                hash_ctx,
                sign_ctx,

                prov_buffer,
                1024,

                sig_buffer,
                (size_t)max_sig,

                &hash_ns,
                &construct_ns,
                &sign_ns,
                &total_ns,

                &provenance_len,
                &signature_len
            );

        if (!ok)
            all_ok = 0;

        fprintf(
            timings,
            "%s,%d,%s,%d,%zu,%s,%zu,%zu,"
            "%llu,%llu,%llu,%llu,%zu,%d\n",

            run_name,
            block,
            alg_name(alg),
            position,
            i + 1,
            records[i].image_name,
            records[i].image_len,
            provenance_len,

            (unsigned long long)hash_ns,
            (unsigned long long)construct_ns,
            (unsigned long long)sign_ns,
            (unsigned long long)total_ns,

            signature_len,
            ok
        );
    }

    fflush(timings);

    OPENSSL_free(sig_buffer);
    free(prov_buffer);

    EVP_MD_CTX_free(hash_ctx);
    EVP_MD_CTX_free(sign_ctx);

    EVP_PKEY_free(key);

    return all_ok;
}

static int warmup_algorithm(
    int alg,
    Record *records,
    size_t count,
    EVP_MD *sha256_md
)
{
    uint64_t key_ns = 0;

    EVP_PKEY *key =
        generate_key(alg, &key_ns);

    if (!key)
        return 0;

    int max_sig =
        EVP_PKEY_get_size(key);

    unsigned char *sig_buffer =
        OPENSSL_malloc(
            (size_t)max_sig
        );

    char *prov_buffer =
        malloc(1024);

    EVP_MD_CTX *hash_ctx =
        EVP_MD_CTX_new();

    EVP_MD_CTX *sign_ctx =
        EVP_MD_CTX_new();

    if (
        !sig_buffer ||
        !prov_buffer ||
        !hash_ctx ||
        !sign_ctx
    ) {
        OPENSSL_free(sig_buffer);
        free(prov_buffer);
        EVP_MD_CTX_free(hash_ctx);
        EVP_MD_CTX_free(sign_ctx);
        EVP_PKEY_free(key);

        return 0;
    }

    for (size_t i = 0; i < count; i++) {

        uint64_t a, b, c, d;
        size_t p, s;

        if (
            !run_e2e_one(
                alg,
                key,
                sha256_md,
                &records[i],

                hash_ctx,
                sign_ctx,

                prov_buffer,
                1024,

                sig_buffer,
                (size_t)max_sig,

                &a, &b, &c, &d,
                &p, &s
            )
        ) {
            OPENSSL_free(sig_buffer);
            free(prov_buffer);
            EVP_MD_CTX_free(hash_ctx);
            EVP_MD_CTX_free(sign_ctx);
            EVP_PKEY_free(key);

            return 0;
        }
    }

    OPENSSL_free(sig_buffer);
    free(prov_buffer);

    EVP_MD_CTX_free(hash_ctx);
    EVP_MD_CTX_free(sign_ctx);

    EVP_PKEY_free(key);

    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 6) {

        fprintf(
            stderr,
            "Usage: %s RECORDS BLOCKS WARMUPS SEED RUN_NAME\n",
            argv[0]
        );

        return 1;
    }

    size_t requested =
        (size_t)strtoul(
            argv[1],
            NULL,
            10
        );

    int blocks =
        atoi(argv[2]);

    int warmups =
        atoi(argv[3]);

    uint64_t seed =
        strtoull(
            argv[4],
            NULL,
            10
        );

    const char *run_name =
        argv[5];

    if (
        requested == 0 ||
        blocks <= 0 ||
        warmups < 0
    ) {
        fprintf(
            stderr,
            "Invalid arguments\n"
        );

        return 1;
    }

    const char *home =
        getenv("HOME");

    if (!home) {
        fprintf(
            stderr,
            "HOME not set\n"
        );

        return 1;
    }

    char manifest_path[PATH_MAX];
    char image_dir[PATH_MAX];
    char provenance_dir[PATH_MAX];

    char timings_path[PATH_MAX];
    char keygen_path[PATH_MAX];
    char schedule_path[PATH_MAX];

    snprintf(
        manifest_path,
        sizeof(manifest_path),

        "%s/pq_ophthalmology/data/derived/"
        "HYGD_v1.1.0_manifest.csv",

        home
    );

    snprintf(
        image_dir,
        sizeof(image_dir),

        "%s/pq_ophthalmology/data/raw/"
        "HYGD_v1.1.0/Images",

        home
    );

    snprintf(
        provenance_dir,
        sizeof(provenance_dir),

        "%s/pq_ophthalmology/data/derived/"
        "provenance/all",

        home
    );

    snprintf(
        timings_path,
        sizeof(timings_path),

        "%s/pq_ophthalmology/results/raw/benchmark/"
        "%s_e2e_timings.csv",

        home,
        run_name
    );

    snprintf(
        keygen_path,
        sizeof(keygen_path),

        "%s/pq_ophthalmology/results/raw/benchmark/"
        "%s_e2e_keygen.csv",

        home,
        run_name
    );

    snprintf(
        schedule_path,
        sizeof(schedule_path),

        "%s/pq_ophthalmology/results/raw/benchmark/"
        "%s_e2e_schedule.csv",

        home,
        run_name
    );

    Record *records = NULL;

    size_t count =
        load_records(
            manifest_path,
            image_dir,
            provenance_dir,
            &records,
            requested
        );

    if (count != requested) {

        fprintf(
            stderr,
            "Requested %zu records, loaded %zu\n",
            requested,
            count
        );

        free_records(
            records,
            count
        );

        return 1;
    }

    EVP_MD *sha256_md =
        EVP_MD_fetch(
            NULL,
            "SHA256",
            NULL
        );

    if (!sha256_md) {

        fprintf(
            stderr,
            "Unable to fetch SHA256\n"
        );

        free_records(
            records,
            count
        );

        return 1;
    }

    printf(
        "OpenSSL: %s\n",
        OpenSSL_version(
            OPENSSL_VERSION
        )
    );

    printf(
        "Records loaded: %zu\n",
        count
    );

    printf(
        "Blocks: %d\n",
        blocks
    );

    printf(
        "Warmups: %d\n",
        warmups
    );

    printf(
        "Seed: %llu\n",
        (unsigned long long)seed
    );

    printf(
        "Run name: %s\n\n",
        run_name
    );

    printf(
        "Checking canonical provenance reproduction...\n"
    );

    if (
        !preflight_canonicalization(
            records,
            count,
            sha256_md
        )
    ) {

        fprintf(
            stderr,
            "Canonicalization preflight FAILED\n"
        );

        EVP_MD_free(sha256_md);

        free_records(
            records,
            count
        );

        return 1;
    }

    printf(
        "Canonicalization preflight: PASS (%zu/%zu)\n\n",
        count,
        count
    );

    printf("Starting warm-up...\n");

    for (int w = 0; w < warmups; w++) {

        int first =
            (w % 2 == 0)
            ? ALG_ECDSA
            : ALG_MLDSA;

        int second =
            first == ALG_ECDSA
            ? ALG_MLDSA
            : ALG_ECDSA;

        printf(
            "Warm-up %d/%d: %s then %s\n",
            w + 1,
            warmups,
            alg_name(first),
            alg_name(second)
        );

        if (
            !warmup_algorithm(
                first,
                records,
                count,
                sha256_md
            )
            ||
            !warmup_algorithm(
                second,
                records,
                count,
                sha256_md
            )
        ) {

            fprintf(
                stderr,
                "Warm-up failure\n"
            );

            EVP_MD_free(sha256_md);

            free_records(
                records,
                count
            );

            return 1;
        }
    }

    printf(
        "Warm-up complete.\n\n"
    );

    FILE *timings =
        fopen(timings_path, "w");

    FILE *keygen =
        fopen(keygen_path, "w");

    FILE *schedule =
        fopen(schedule_path, "w");

    if (
        !timings ||
        !keygen ||
        !schedule
    ) {

        perror("output");

        if (timings)
            fclose(timings);

        if (keygen)
            fclose(keygen);

        if (schedule)
            fclose(schedule);

        EVP_MD_free(sha256_md);

        free_records(
            records,
            count
        );

        return 1;
    }

    fprintf(
        timings,

        "run,block,algorithm,order_position,"
        "record_index,image_name,image_bytes,"
        "provenance_bytes,hash_ns,construct_ns,"
        "sign_ns,e2e_ns,signature_bytes,sign_ok\n"
    );

    fprintf(
        keygen,

        "run,block,algorithm,order_position,"
        "keygen_ns,keygen_ok\n"
    );

    fprintf(
        schedule,

        "block,first_algorithm,second_algorithm\n"
    );

    int *first_alg =
        malloc(
            (size_t)blocks
            * sizeof(int)
        );

    if (!first_alg) {

        fclose(timings);
        fclose(keygen);
        fclose(schedule);

        EVP_MD_free(sha256_md);

        free_records(
            records,
            count
        );

        return 1;
    }

    build_schedule(
        first_alg,
        blocks,
        seed
    );

    int overall_ok = 1;

    for (int b = 0; b < blocks; b++) {

        int first =
            first_alg[b];

        int second =
            first == ALG_ECDSA
            ? ALG_MLDSA
            : ALG_ECDSA;

        fprintf(
            schedule,

            "%d,%s,%s\n",

            b + 1,
            alg_name(first),
            alg_name(second)
        );

        fflush(schedule);

        printf(
            "Block %d/%d: %s then %s\n",
            b + 1,
            blocks,
            alg_name(first),
            alg_name(second)
        );

        int ok1 =
            run_algorithm_block(
                run_name,
                b + 1,
                1,
                first,
                records,
                count,
                sha256_md,
                timings,
                keygen
            );

        int ok2 =
            run_algorithm_block(
                run_name,
                b + 1,
                2,
                second,
                records,
                count,
                sha256_md,
                timings,
                keygen
            );

        if (!ok1 || !ok2) {
            overall_ok = 0;
            break;
        }
    }

    free(first_alg);

    fclose(timings);
    fclose(keygen);
    fclose(schedule);

    EVP_MD_free(sha256_md);

    free_records(
        records,
        count
    );

    if (!overall_ok) {

        fprintf(
            stderr,
            "End-to-end benchmark failed\n"
        );

        return 2;
    }

    printf(
        "\nEnd-to-end benchmark completed successfully.\n"
    );

    printf(
        "Timings: %s\n",
        timings_path
    );

    printf(
        "Key generation: %s\n",
        keygen_path
    );

    printf(
        "Schedule: %s\n",
        schedule_path
    );

    return 0;
}
