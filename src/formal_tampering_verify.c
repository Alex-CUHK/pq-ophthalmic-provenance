#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

enum {
    ALG_ECDSA = 0,
    ALG_MLDSA = 1
};

typedef struct {
    unsigned char *data;
    size_t len;
} Blob;

typedef struct {
    char *name;

    Blob original;
    Blob label;
    Blob quality;
    Blob identifier;
} Case;


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

    if (out == NULL)
        return NULL;

    memcpy(out, s, n + 1);

    return out;
}


static int read_file(
    const char *path,
    Blob *out
)
{
    FILE *f = fopen(path, "rb");

    if (f == NULL) {
        fprintf(stderr, "Cannot open: %s\n", path);
        return 0;
    }

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

    out->data = buf;
    out->len = got;

    return 1;
}


static void free_blob(Blob *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
}


static EVP_PKEY *generate_key(int alg)
{
    if (alg == ALG_ECDSA) {
        return EVP_PKEY_Q_keygen(
            NULL,
            NULL,
            "EC",
            "P-256"
        );
    }

    return EVP_PKEY_Q_keygen(
        NULL,
        NULL,
        "ML-DSA-65"
    );
}


static int sign_blob(
    int alg,
    EVP_PKEY *key,
    const Blob *message,
    unsigned char **sig_out,
    size_t *sig_len_out
)
{
    int max_sig = EVP_PKEY_get_size(key);

    if (max_sig <= 0)
        return 0;

    unsigned char *sig =
        OPENSSL_malloc((size_t)max_sig);

    EVP_MD_CTX *ctx =
        EVP_MD_CTX_new();

    if (sig == NULL || ctx == NULL) {
        OPENSSL_free(sig);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    size_t sig_len =
        (size_t)max_sig;

    ERR_clear_error();

    int rc;

    if (alg == ALG_ECDSA) {

        rc = EVP_DigestSignInit_ex(
            ctx,
            NULL,
            "SHA256",
            NULL,
            NULL,
            key,
            NULL
        );

    } else {

        rc = EVP_DigestSignInit_ex(
            ctx,
            NULL,
            NULL,
            NULL,
            NULL,
            key,
            NULL
        );
    }

    if (rc == 1) {
        rc = EVP_DigestSign(
            ctx,
            sig,
            &sig_len,
            message->data,
            message->len
        );
    }

    EVP_MD_CTX_free(ctx);

    if (rc != 1) {
        fprintf(stderr, "Signing error:\n");
        ERR_print_errors_fp(stderr);
        ERR_clear_error();

        OPENSSL_free(sig);

        return 0;
    }

    *sig_out = sig;
    *sig_len_out = sig_len;

    return 1;
}


/*
Return values:

 1  = signature VALID
 0  = signature INVALID (expected tamper detection)
-1  = technical OpenSSL error
*/
static int verify_blob(
    int alg,
    EVP_PKEY *key,
    const Blob *message,
    const unsigned char *sig,
    size_t sig_len
)
{
    EVP_MD_CTX *ctx =
        EVP_MD_CTX_new();

    if (ctx == NULL)
        return -1;

    ERR_clear_error();

    int rc;

    if (alg == ALG_ECDSA) {

        rc = EVP_DigestVerifyInit_ex(
            ctx,
            NULL,
            "SHA256",
            NULL,
            NULL,
            key,
            NULL
        );

    } else {

        rc = EVP_DigestVerifyInit_ex(
            ctx,
            NULL,
            NULL,
            NULL,
            NULL,
            key,
            NULL
        );
    }

    if (rc != 1) {
        EVP_MD_CTX_free(ctx);

        fprintf(stderr, "Verification init error:\n");
        ERR_print_errors_fp(stderr);
        ERR_clear_error();

        return -1;
    }

    rc = EVP_DigestVerify(
        ctx,
        sig,
        sig_len,
        message->data,
        message->len
    );

    EVP_MD_CTX_free(ctx);

    if (rc == 1) {
        ERR_clear_error();
        return 1;
    }

    if (rc == 0) {
        /*
        Invalid signature is expected for
        deliberately tampered messages.
        */
        ERR_clear_error();
        return 0;
    }

    fprintf(stderr, "Technical verification error:\n");
    ERR_print_errors_fp(stderr);
    ERR_clear_error();

    return -1;
}


static int load_cases(
    const char *manifest_path,
    const char *original_dir,
    const char *label_dir,
    const char *quality_dir,
    const char *identifier_dir,
    Case **out_cases,
    size_t *out_count
)
{
    FILE *f =
        fopen(manifest_path, "r");

    if (f == NULL) {
        perror("manifest");
        return 0;
    }

    const size_t expected = 747;

    Case *cases =
        calloc(expected, sizeof(Case));

    if (cases == NULL) {
        fclose(f);
        return 0;
    }

    char line[8192];

    /* Skip CSV header */
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        free(cases);
        return 0;
    }

    size_t count = 0;

    while (
        count < expected &&
        fgets(line, sizeof(line), f) != NULL
    ) {
        char *save = NULL;

        /*
        provenance_manifest.csv:
        image_name,
        provenance_file,
        provenance_sha256,
        provenance_size_bytes
        */

        char *image_name =
            strtok_r(line, ",", &save);

        char *prov_file =
            strtok_r(NULL, ",", &save);

        (void)image_name;

        if (prov_file == NULL)
            continue;

        cases[count].name =
            copy_string(prov_file);

        if (cases[count].name == NULL)
            break;

        char path[PATH_MAX];

        snprintf(
            path,
            sizeof(path),
            "%s/%s",
            original_dir,
            prov_file
        );

        if (!read_file(
                path,
                &cases[count].original
            ))
            break;

        snprintf(
            path,
            sizeof(path),
            "%s/%s",
            label_dir,
            prov_file
        );

        if (!read_file(
                path,
                &cases[count].label
            ))
            break;

        snprintf(
            path,
            sizeof(path),
            "%s/%s",
            quality_dir,
            prov_file
        );

        if (!read_file(
                path,
                &cases[count].quality
            ))
            break;

        snprintf(
            path,
            sizeof(path),
            "%s/%s",
            identifier_dir,
            prov_file
        );

        if (!read_file(
                path,
                &cases[count].identifier
            ))
            break;

        count++;
    }

    fclose(f);

    if (count != expected) {

        fprintf(
            stderr,
            "Expected 747 cases, loaded %zu\n",
            count
        );

        for (size_t i = 0; i <= count && i < expected; i++) {
            free(cases[i].name);
            free_blob(&cases[i].original);
            free_blob(&cases[i].label);
            free_blob(&cases[i].quality);
            free_blob(&cases[i].identifier);
        }

        free(cases);

        return 0;
    }

    *out_cases = cases;
    *out_count = count;

    return 1;
}


static void free_cases(
    Case *cases,
    size_t count
)
{
    for (size_t i = 0; i < count; i++) {

        free(cases[i].name);

        free_blob(&cases[i].original);
        free_blob(&cases[i].label);
        free_blob(&cases[i].quality);
        free_blob(&cases[i].identifier);
    }

    free(cases);
}


int main(void)
{
    const char *home =
        getenv("HOME");

    if (home == NULL) {
        fprintf(stderr, "HOME not set\n");
        return 1;
    }

    char manifest[PATH_MAX];

    char original_dir[PATH_MAX];
    char label_dir[PATH_MAX];
    char quality_dir[PATH_MAX];
    char identifier_dir[PATH_MAX];

    char output_path[PATH_MAX];

    snprintf(
        manifest,
        sizeof(manifest),
        "%s/pq_ophthalmology/data/derived/provenance/"
        "provenance_manifest.csv",
        home
    );

    snprintf(
        original_dir,
        sizeof(original_dir),
        "%s/pq_ophthalmology/data/derived/provenance/all",
        home
    );

    snprintf(
        label_dir,
        sizeof(label_dir),
        "%s/pq_ophthalmology/data/derived/tampering/"
        "formal_v1/label",
        home
    );

    snprintf(
        quality_dir,
        sizeof(quality_dir),
        "%s/pq_ophthalmology/data/derived/tampering/"
        "formal_v1/quality",
        home
    );

    snprintf(
        identifier_dir,
        sizeof(identifier_dir),
        "%s/pq_ophthalmology/data/derived/tampering/"
        "formal_v1/identifier",
        home
    );

    snprintf(
        output_path,
        sizeof(output_path),
        "%s/pq_ophthalmology/results/raw/tampering/"
        "formal_v1/formal_metadata_tampering.csv",
        home
    );

    Case *cases = NULL;
    size_t count = 0;

    if (!load_cases(
            manifest,
            original_dir,
            label_dir,
            quality_dir,
            identifier_dir,
            &cases,
            &count
        )) {

        return 1;
    }

    FILE *out =
        fopen(output_path, "w");

    if (out == NULL) {
        perror("output");
        free_cases(cases, count);
        return 1;
    }

    fprintf(
        out,
        "record_index,provenance_file,algorithm,"
        "signature_bytes,sign_ok,"
        "original_verify_rc,"
        "label_verify_rc,label_detected,"
        "quality_verify_rc,quality_detected,"
        "identifier_verify_rc,identifier_detected,"
        "technical_error\n"
    );

    int overall_ok = 1;

    printf(
        "OpenSSL: %s\n",
        OpenSSL_version(OPENSSL_VERSION)
    );

    printf("Cases loaded: %zu\n\n", count);


    for (int alg = ALG_ECDSA;
         alg <= ALG_MLDSA;
         alg++) {

        printf(
            "Testing %s...\n",
            alg_name(alg)
        );

        EVP_PKEY *key =
            generate_key(alg);

        if (key == NULL) {
            fprintf(stderr, "Key generation failed\n");
            ERR_print_errors_fp(stderr);

            fclose(out);
            free_cases(cases, count);

            return 1;
        }

        int sign_success = 0;
        int original_pass = 0;

        int label_detected = 0;
        int quality_detected = 0;
        int identifier_detected = 0;

        int technical_errors = 0;


        for (size_t i = 0; i < count; i++) {

            unsigned char *sig = NULL;
            size_t sig_len = 0;

            int sign_ok =
                sign_blob(
                    alg,
                    key,
                    &cases[i].original,
                    &sig,
                    &sig_len
                );

            if (sign_ok)
                sign_success++;

            int original_rc = -1;
            int label_rc = -1;
            int quality_rc = -1;
            int identifier_rc = -1;

            if (sign_ok) {

                original_rc =
                    verify_blob(
                        alg,
                        key,
                        &cases[i].original,
                        sig,
                        sig_len
                    );

                label_rc =
                    verify_blob(
                        alg,
                        key,
                        &cases[i].label,
                        sig,
                        sig_len
                    );

                quality_rc =
                    verify_blob(
                        alg,
                        key,
                        &cases[i].quality,
                        sig,
                        sig_len
                    );

                identifier_rc =
                    verify_blob(
                        alg,
                        key,
                        &cases[i].identifier,
                        sig,
                        sig_len
                    );
            }

            int label_hit =
                (label_rc == 0);

            int quality_hit =
                (quality_rc == 0);

            int identifier_hit =
                (identifier_rc == 0);

            int technical_error =
                (
                    !sign_ok ||
                    original_rc < 0 ||
                    label_rc < 0 ||
                    quality_rc < 0 ||
                    identifier_rc < 0
                );

            if (original_rc == 1)
                original_pass++;

            if (label_hit)
                label_detected++;

            if (quality_hit)
                quality_detected++;

            if (identifier_hit)
                identifier_detected++;

            if (technical_error)
                technical_errors++;

            fprintf(
                out,
                "%zu,%s,%s,%zu,%d,"
                "%d,%d,%d,%d,%d,%d,%d,%d\n",

                i + 1,
                cases[i].name,
                alg_name(alg),
                sig_len,
                sign_ok,

                original_rc,

                label_rc,
                label_hit,

                quality_rc,
                quality_hit,

                identifier_rc,
                identifier_hit,

                technical_error
            );

            OPENSSL_free(sig);
        }

        fflush(out);

        printf(
            "  Signing success:       %d / 747\n",
            sign_success
        );

        printf(
            "  Original verification: %d / 747 PASS\n",
            original_pass
        );

        printf(
            "  Label tampering:       %d / 747 DETECTED\n",
            label_detected
        );

        printf(
            "  Quality tampering:     %d / 747 DETECTED\n",
            quality_detected
        );

        printf(
            "  Identifier tampering:  %d / 747 DETECTED\n",
            identifier_detected
        );

        printf(
            "  Technical errors:      %d\n\n",
            technical_errors
        );


        if (
            sign_success != 747 ||
            original_pass != 747 ||
            label_detected != 747 ||
            quality_detected != 747 ||
            identifier_detected != 747 ||
            technical_errors != 0
        ) {
            overall_ok = 0;
        }

        EVP_PKEY_free(key);
    }

    fclose(out);
    free_cases(cases, count);

    printf("===============================\n");

    printf(
        "FINAL METADATA VALIDATION: %s\n",
        overall_ok ? "PASS" : "FAIL"
    );

    printf("===============================\n");

    printf("\nRaw results:\n%s\n", output_path);

    return overall_ok ? 0 : 2;
}
