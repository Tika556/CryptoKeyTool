#include <iostream>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

EC_KEY* generate_key() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == nullptr || !EC_KEY_generate_key(key)) {
        handleErrors();
    }
    return key;
}

EC_POINT* add_public_keys(const EC_GROUP *group, const EC_POINT *key1, const EC_POINT *key2) {
    EC_POINT *result = EC_POINT_new(group);
    if (result == nullptr || !EC_POINT_add(group, result, key1, key2, nullptr)) {
        handleErrors();
    }
    return result;
}

EC_POINT* subtract_public_keys(const EC_GROUP *group, const EC_POINT *key1, const EC_POINT *key2) {
    EC_POINT *neg_key2 = EC_POINT_new(group);
    EC_POINT *result = EC_POINT_new(group);
    if (neg_key2 == nullptr || result == nullptr ||
        !EC_POINT_invert(group, neg_key2, key2, nullptr) ||
        !EC_POINT_add(group, result, key1, neg_key2, nullptr)) {
        handleErrors();
    }
    EC_POINT_free(neg_key2);
    return result;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate two EC keys
    EC_KEY *key1 = generate_key();
    EC_KEY *key2 = generate_key();

    const EC_GROUP *group = EC_KEY_get0_group(key1);
    const EC_POINT *pub_key1 = EC_KEY_get0_public_key(key1);
    const EC_POINT *pub_key2 = EC_KEY_get0_public_key(key2);

    // Add public keys
    EC_POINT *sum = add_public_keys(group, pub_key1, pub_key2);
    // Subtract public keys
    EC_POINT *difference = subtract_public_keys(group, pub_key1, pub_key2);

    // Print results (in hex form for simplicity)
    char *sum_hex = EC_POINT_point2hex(group, sum, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    char *diff_hex = EC_POINT_point2hex(group, difference, POINT_CONVERSION_UNCOMPRESSED, nullptr);

    std::cout << "Sum: " << sum_hex << std::endl;
    std::cout << "Difference: " << diff_hex << std::endl;

    // Cleanup
    EC_KEY_free(key1);
    EC_KEY_free(key2);
    EC_POINT_free(sum);
    EC_POINT_free(difference);
    OPENSSL_free(sum_hex);
    OPENSSL_free(diff_hex);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
