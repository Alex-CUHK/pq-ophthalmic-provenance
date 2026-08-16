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
    char *name;
    unsigned char *data;
    size_t len;
} Record;

typedef struct {
    unsigned char *data;
    size_t len;
} Signature;

static uint64_t now_ns(void)
{
    struct timespec ts;

#ifdef CLOCK_MONOTONIC_RAW
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif

    return ((uint64_t)ts.tv_sec * 1000000000ULL)
           + (uint64_t)ts.tv_nsec;
}

static const char *alg_name(int alg)
{
    return alg == ALG_ECDSA
        ? "ECDSA_P256_SHA256"
        : "ML_DSA_65";
}

static EVP_PKEY *generate_key(int alg, uint64_t *elapsed_ns)
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

static int sign_one(
    int alg,
    EVP_PKEY *key,
    const unsigned char *msg,
    size_t msg_len,
    Signature *out,
    uint64_t *elapsed_ns
)
{
    int max_sig = EVP_PKEY_get_size(key);

    if (max_sig <= 0)
        return 0;

    unsigned char *sig = OPENSSL_malloc((size_t)max_sig);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (sig == NULL || ctx == NULL) {
        OPENSSL_free(sig);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    size_t sig_len = (size_t)max_sig;

    ERR_clear_error();

    uint64_t start = now_ns();

    int ok;

    if (alg == ALG_ECDSA) {
        ok = EVP_DigestSignInit_ex(
            ctx,
            NULL,
            "SHA256",
            NULL,
            NULL,
            key,
            NULL
        );
    } else {
        ok = EVP_DigestSignInit_ex(
            ctx,
            NULL,
            NULL,
            NULL,
            NULL,
            key,
            NULL
        );
    }

    if (ok == 1) {
        ok = EVP_DigestSign(
            ctx,
            sig,
            &sig_len,
            msg,
            msg_len
        );
    }

    uint64_t end = now_ns();

    *elapsed_ns = end - start;

    EVP_MD_CTX_free(ctx);

    if (ok != 1) {
        OPENSSL_free(sig);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    out->data = sig;
    out->len = sig_len;

    return 1;
}

static int verify_one(
    int alg,
    EVP_PKEY *key,
    const unsigned char *msg,
    size_t msg_len,
    const Signature *sig,
    uint64_t *elapsed_ns
)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
        return 0;

    ERR_clear_error();

    uint64_t start = now_ns();

    int ok;

    if (alg == ALG_ECDSA) {
        ok = EVP_DigestVerifyInit_ex(
            ctx,
            NULL,
            "SHA256",
            NULL,
            NULL,
            key,
            NULL
        );
    } else {
        ok = EVP_DigestVerifyInit_ex(
            ctx,
            NULL,
            NULL,
            NULL,
            NULL,
            key,
            NULL
        );
    }

    if (ok == 1) {
        ok = EVP_DigestVerify(
            ctx,
            sig->data,
            sig->len,
            msg,
            msg_len
        );
    }

    uint64_t end = now_ns();

    *elapsed_ns = end - start;

    EVP_MD_CTX_free(ctx);

    if (ok != 1) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return 1;
}

static int read_file(
    const char *path,
    unsigned char **data,
    size_t *len
)
{
    FILE *f = fopen(path, "rb");

    if (f == NULL)
        return 0;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }

    long size = ftell(f);

    if (size < 0) {
        fclose(f);
        return 0;
    }

    rewind(f);

    unsigned char *buf =
        malloc(size > 0 ? (size_t)size : 1);

    if (buf == NULL) {
        fclose(f);
        return 0;
    }

    size_t got =
        fread(buf, 1, (size_t)size, f);

    fclose(f);

    if (got != (size_t)size) {
        free(buf);
        return 0;
    }

    *data = buf;
    *len = got;

    return 1;
}

static char *copy_string(const char *s)
{
    size_t n = strlen(s);

    char *out = malloc(n + 1);

    if (out == NULL)
        return NULL;

    memcpy(out, s, n + 1);

    return out;
}

static size_t load_records(
    const char *manifest_path,
    const char *data_dir,
    Record **out_records,
    size_t requested
)
{
    FILE *f = fopen(manifest_path, "r");

    if (f == NULL) {
        perror("manifest");
        return 0;
    }

    Record *records =
        calloc(requested, sizeof(Record));

    if (records == NULL) {
        fclose(f);
        return 0;
    }

    char line[8192];

    /* Skip header */
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        free(records);
        return 0;
    }

    size_t count = 0;

    while (
        count < requested &&
        fgets(line, sizeof(line), f) != NULL
    ) {
        char *save = NULL;

        char *image_name =
            strtok_r(line, ",", &save);

        char *provenance_file =
            strtok_r(NULL, ",", &save);

        (void)image_name;

        if (provenance_file == NULL)
            continue;

        char path[PATH_MAX];

        snprintf(
            path,
            sizeof(path),
            "%s/%s",
            data_dir,
            provenance_file
        );

        records[count].name =
            copy_string(provenance_file);

        if (records[count].name == NULL)
            break;

        if (!read_file(
                path,
                &records[count].data,
                &records[count].len
            )) {
            fprintf(
                stderr,
                "Failed to read: %s\n",
                path
            );
            free(records[count].name);
            records[count].name = NULL;
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
        free(records[i].name);
        free(records[i].data);
    }

    free(records);
}

static int warmup_algorithm(
    int alg,
    Record *records,
    size_t count
)
{
    uint64_t key_ns = 0;

    EVP_PKEY *key =
        generate_key(alg, &key_ns);

    if (key == NULL)
        return 0;

    for (size_t i = 0; i < count; i++) {

        Signature sig = {0};
        uint64_t sign_ns = 0;
        uint64_t verify_ns = 0;

        if (!sign_one(
                alg,
                key,
                records[i].data,
                records[i].len,
                &sig,
                &sign_ns
            )) {
            EVP_PKEY_free(key);
            return 0;
        }

        if (!verify_one(
                alg,
                key,
                records[i].data,
                records[i].len,
                &sig,
                &verify_ns
            )) {
            OPENSSL_free(sig.data);
            EVP_PKEY_free(key);
            return 0;
        }

        OPENSSL_free(sig.data);
    }

    EVP_PKEY_free(key);

    return 1;
}

/* Deterministic SplitMix64 RNG */
static uint64_t rng_state;

static uint64_t rng_next(void)
{
    uint64_t z =
        (rng_state += 0x9e3779b97f4a7c15ULL);

    z = (z ^ (z >> 30))
        * 0xbf58476d1ce4e5b9ULL;

    z = (z ^ (z >> 27))
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
            (i < half)
            ? ALG_ECDSA
            : ALG_MLDSA;
    }

    rng_state = seed;

    for (int i = blocks - 1; i > 0; i--) {

        int j =
            (int)(rng_next() % (uint64_t)(i + 1));

        int tmp = first_alg[i];
        first_alg[i] = first_alg[j];
        first_alg[j] = tmp;
    }
}

static int run_algorithm_block(
    const char *run_name,
    int block,
    int order_position,
    int alg,
    Record *records,
    size_t count,
    FILE *timings,
    FILE *keygen
)
{
    uint64_t keygen_ns = 0;

    EVP_PKEY *key =
        generate_key(alg, &keygen_ns);

    int key_ok = key != NULL;

    fprintf(
        keygen,
        "%s,%d,%s,%d,%llu,%d\n",
        run_name,
        block,
        alg_name(alg),
        order_position,
        (unsigned long long)keygen_ns,
        key_ok
    );

    fflush(keygen);

    if (!key_ok) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    Signature *sigs =
        calloc(count, sizeof(Signature));

    uint64_t *sign_times =
        calloc(count, sizeof(uint64_t));

    uint64_t *verify_times =
        calloc(count, sizeof(uint64_t));

    int *sign_ok =
        calloc(count, sizeof(int));

    int *verify_ok =
        calloc(count, sizeof(int));

    if (
        sigs == NULL ||
        sign_times == NULL ||
        verify_times == NULL ||
        sign_ok == NULL ||
        verify_ok == NULL
    ) {
        fprintf(stderr, "Allocation failure\n");

        free(sigs);
        free(sign_times);
        free(verify_times);
        free(sign_ok);
        free(verify_ok);

        EVP_PKEY_free(key);

        return 0;
    }

    /* Signing phase */
    for (size_t i = 0; i < count; i++) {

        sign_ok[i] = sign_one(
            alg,
            key,
            records[i].data,
            records[i].len,
            &sigs[i],
            &sign_times[i]
        );
    }

    /* Verification phase */
    for (size_t i = 0; i < count; i++) {

        if (sign_ok[i]) {
            verify_ok[i] = verify_one(
                alg,
                key,
                records[i].data,
                records[i].len,
                &sigs[i],
                &verify_times[i]
            );
        }
    }

    int all_ok = 1;

    for (size_t i = 0; i < count; i++) {

        if (!sign_ok[i] || !verify_ok[i])
            all_ok = 0;

        fprintf(
            timings,
            "%s,%d,%s,%d,%zu,%s,%zu,"
            "%llu,%llu,%zu,%d,%d\n",

            run_name,
            block,
            alg_name(alg),
            order_position,
            i + 1,
            records[i].name,
            records[i].len,
            (unsigned long long)sign_times[i],
            (unsigned long long)verify_times[i],
            sigs[i].len,
            sign_ok[i],
            verify_ok[i]
        );
    }

    fflush(timings);

    for (size_t i = 0; i < count; i++)
        OPENSSL_free(sigs[i].data);

    free(sigs);
    free(sign_times);
    free(verify_times);
    free(sign_ok);
    free(verify_ok);

    EVP_PKEY_free(key);

    return all_ok;
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
        (size_t)strtoul(argv[1], NULL, 10);

    int blocks =
        atoi(argv[2]);

    int warmups =
        atoi(argv[3]);

    uint64_t seed =
        strtoull(argv[4], NULL, 10);

    const char *run_name =
        argv[5];

    if (
        requested == 0 ||
        blocks <= 0 ||
        warmups < 0
    ) {
        fprintf(stderr, "Invalid arguments\n");
        return 1;
    }

    const char *home =
        getenv("HOME");

    if (home == NULL) {
        fprintf(stderr, "HOME is not set\n");
        return 1;
    }

    char manifest_path[PATH_MAX];
    char data_dir[PATH_MAX];
    char timings_path[PATH_MAX];
    char keygen_path[PATH_MAX];
    char schedule_path[PATH_MAX];

    snprintf(
        manifest_path,
        sizeof(manifest_path),
        "%s/pq_ophthalmology/data/derived/provenance/"
        "provenance_manifest.csv",
        home
    );

    snprintf(
        data_dir,
        sizeof(data_dir),
        "%s/pq_ophthalmology/data/derived/provenance/all",
        home
    );

    snprintf(
        timings_path,
        sizeof(timings_path),
        "%s/pq_ophthalmology/results/raw/benchmark/"
        "%s_timings.csv",
        home,
        run_name
    );

    snprintf(
        keygen_path,
        sizeof(keygen_path),
        "%s/pq_ophthalmology/results/raw/benchmark/"
        "%s_keygen.csv",
        home,
        run_name
    );

    snprintf(
        schedule_path,
        sizeof(schedule_path),
        "%s/pq_ophthalmology/results/raw/benchmark/"
        "%s_schedule.csv",
        home,
        run_name
    );

    Record *records = NULL;

    size_t count =
        load_records(
            manifest_path,
            data_dir,
            &records,
            requested
        );

    if (count != requested) {
        fprintf(
            stderr,
            "Requested %zu records but loaded %zu\n",
            requested,
            count
        );

        free_records(records, count);

        return 1;
    }

    printf("OpenSSL: %s\n",
           OpenSSL_version(OPENSSL_VERSION));

    printf("Records loaded: %zu\n", count);
    printf("Blocks: %d\n", blocks);
    printf("Warmups: %d\n", warmups);
    printf("Seed: %llu\n",
           (unsigned long long)seed);

    printf("Run name: %s\n\n", run_name);

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
            !warmup_algorithm(first, records, count) ||
            !warmup_algorithm(second, records, count)
        ) {
            fprintf(stderr, "Warm-up failed\n");

            free_records(records, count);

            return 1;
        }
    }

    printf("Warm-up complete.\n\n");

    FILE *timings =
        fopen(timings_path, "w");

    FILE *keygen =
        fopen(keygen_path, "w");

    FILE *schedule =
        fopen(schedule_path, "w");

    if (
        timings == NULL ||
        keygen == NULL ||
        schedule == NULL
    ) {
        perror("output");

        if (timings) fclose(timings);
        if (keygen) fclose(keygen);
        if (schedule) fclose(schedule);

        free_records(records, count);

        return 1;
    }

    fprintf(
        timings,
        "run,block,algorithm,order_position,"
        "record_index,provenance_file,message_bytes,"
        "sign_ns,verify_ns,signature_bytes,"
        "sign_ok,verify_ok\n"
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
        malloc((size_t)blocks * sizeof(int));

    if (first_alg == NULL) {
        fclose(timings);
        fclose(keygen);
        fclose(schedule);

        free_records(records, count);

        return 1;
    }

    build_schedule(
        first_alg,
        blocks,
        seed
    );

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
                timings,
                keygen
            );

        if (!ok1 || !ok2) {

            fprintf(
                stderr,
                "Failure detected in block %d\n",
                b + 1
            );

            free(first_alg);

            fclose(timings);
            fclose(keygen);
            fclose(schedule);

            free_records(records, count);

            return 2;
        }
    }

    free(first_alg);

    fclose(timings);
    fclose(keygen);
    fclose(schedule);

    free_records(records, count);

    printf("\nBenchmark completed successfully.\n");
    printf("Timings: %s\n", timings_path);
    printf("Key generation: %s\n", keygen_path);
    printf("Schedule: %s\n", schedule_path);

    return 0;
}
