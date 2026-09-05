#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static unsigned char *read_file(
    const char *path,
    size_t *len
)
{
    FILE *f = NULL;
    unsigned char *buf = NULL;
    long size = 0;

    *len = 0;

    f = fopen(path, "rb");

    if (f == NULL)
        return NULL;

    if (fseek(f, 0, SEEK_END) != 0)
        goto fail;

    size = ftell(f);

    if (size < 0)
        goto fail;

    if (fseek(f, 0, SEEK_SET) != 0)
        goto fail;

    buf = malloc(
        size == 0
        ? 1
        : (size_t)size
    );

    if (buf == NULL)
        goto fail;

    if (
        size > 0
        && fread(
            buf,
            1,
            (size_t)size,
            f
        ) != (size_t)size
    )
        goto fail;

    fclose(f);

    *len = (size_t)size;

    return buf;

fail:
    free(buf);

    if (f != NULL)
        fclose(f);

    return NULL;
}

static int expected_pk_size(
    const char *alg
)
{
    if (strcmp(alg, "ML-DSA-44") == 0)
        return 1312;

    if (strcmp(alg, "ML-DSA-65") == 0)
        return 1952;

    if (strcmp(alg, "ML-DSA-87") == 0)
        return 2592;

    return -1;
}

static int expected_sig_size(
    const char *alg
)
{
    if (strcmp(alg, "ML-DSA-44") == 0)
        return 2420;

    if (strcmp(alg, "ML-DSA-65") == 0)
        return 3309;

    if (strcmp(alg, "ML-DSA-87") == 0)
        return 4627;

    return -1;
}

int main(
    int argc,
    char **argv
)
{
    const char *gate;
    const char *alg;

    unsigned char *pk = NULL;
    unsigned char *msg = NULL;
    unsigned char *ctx = NULL;
    unsigned char *sig = NULL;

    size_t pk_len = 0;
    size_t msg_len = 0;
    size_t ctx_len = 0;
    size_t sig_len = 0;

    int expected_valid;
    int ret;
    int actual_valid;

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *vctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sigalg = NULL;

    OSSL_PARAM key_params[2];
    OSSL_PARAM verify_params[2];

    gate = getenv(
        "QSV_EXECUTE_CRYPTO"
    );

    if (
        gate == NULL
        || strcmp(gate, "YES") != 0
    ) {
        fprintf(
            stderr,
            "STOP: QSV_EXECUTE_CRYPTO=YES required\n"
        );

        return 78;
    }

    if (argc != 7) {
        fprintf(
            stderr,
            "usage: %s ALG PK MSG CTX SIG EXPECTED_VALID\n",
            argv[0]
        );

        return 64;
    }

    alg = argv[1];

    if (strcmp(argv[6], "true") == 0)
        expected_valid = 1;

    else if (strcmp(argv[6], "false") == 0)
        expected_valid = 0;

    else
        return 64;

    pk = read_file(
        argv[2],
        &pk_len
    );

    msg = read_file(
        argv[3],
        &msg_len
    );

    ctx = read_file(
        argv[4],
        &ctx_len
    );

    sig = read_file(
        argv[5],
        &sig_len
    );

    if (
        pk == NULL
        || msg == NULL
        || ctx == NULL
        || sig == NULL
    ) {
        ret = 70;
        goto cleanup;
    }

    if (
        expected_pk_size(alg) < 0
        || pk_len
        != (size_t)expected_pk_size(alg)
    ) {
        ret = 70;
        goto cleanup;
    }

    if (
        expected_sig_size(alg) < 0
        || sig_len
        != (size_t)expected_sig_size(alg)
    ) {
        ret = 70;
        goto cleanup;
    }

    if (ctx_len > 255) {
        ret = 70;
        goto cleanup;
    }

    kctx = EVP_PKEY_CTX_new_from_name(
        NULL,
        alg,
        NULL
    );

    if (kctx == NULL) {
        ret = 70;
        goto openssl_error;
    }

    if (
        EVP_PKEY_fromdata_init(kctx)
        <= 0
    ) {
        ret = 70;
        goto openssl_error;
    }

    key_params[0] =
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            pk,
            pk_len
        );

    key_params[1] =
        OSSL_PARAM_construct_end();

    if (
        EVP_PKEY_fromdata(
            kctx,
            &pkey,
            EVP_PKEY_PUBLIC_KEY,
            key_params
        ) <= 0
    ) {
        ret = 70;
        goto openssl_error;
    }

    sigalg = EVP_SIGNATURE_fetch(
        NULL,
        alg,
        NULL
    );

    if (sigalg == NULL) {
        ret = 70;
        goto openssl_error;
    }

    vctx = EVP_PKEY_CTX_new_from_pkey(
        NULL,
        pkey,
        NULL
    );

    if (vctx == NULL) {
        ret = 70;
        goto openssl_error;
    }

    verify_params[0] =
        OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            ctx,
            ctx_len
        );

    verify_params[1] =
        OSSL_PARAM_construct_end();

    if (
        EVP_PKEY_verify_message_init(
            vctx,
            sigalg,
            verify_params
        ) <= 0
    ) {
        ret = 70;
        goto openssl_error;
    }

    ret = EVP_PKEY_verify(
        vctx,
        sig,
        sig_len,
        msg,
        msg_len
    );

    if (ret < 0) {
        fprintf(
            stderr,
            "OPENSSL_OPERATIONAL_ERROR=YES\n"
        );

        ret = 70;
        goto openssl_error;
    }

    actual_valid = (
        ret == 1
    );

    printf(
        "OPENSSL_ACTUAL_VALID=%s\n",
        actual_valid
        ? "true"
        : "false"
    );

    printf(
        "OPENSSL_EXPECTED_VALID=%s\n",
        expected_valid
        ? "true"
        : "false"
    );

    if (
        actual_valid
        != expected_valid
    ) {
        fprintf(
            stderr,
            "OPENSSL_EXPECTATION_MATCH=NO\n"
        );

        ret = 1;
        goto cleanup;
    }

    printf(
        "OPENSSL_EXPECTATION_MATCH=YES\n"
    );

    ret = 0;

    goto cleanup;

openssl_error:
    ERR_print_errors_fp(
        stderr
    );

cleanup:
    EVP_PKEY_CTX_free(vctx);
    EVP_SIGNATURE_free(sigalg);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);

    free(pk);
    free(msg);
    free(ctx);
    free(sig);

    return ret;
}
