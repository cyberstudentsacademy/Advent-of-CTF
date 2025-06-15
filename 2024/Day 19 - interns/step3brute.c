#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>
#include <openssl/sha.h>

/*
    Compile with:
      gcc brute_mask.c -o brute_mask -lgmp -lcrypto

    Usage:
      ./brute_mask <ciphertext_in_decimal>

    This script:
      1) Reads the ciphertext (big integer) from argv[1].
      2) Splits it into c_hi (upper bits) and c_lo (lowest 32 bits).
      3) Loops over all 2^32 possible masks (mask_candidate).
      4) For each mask_candidate:
         - Constructs step3_candidate by substituting the low 32 bits
           (c_lo ^ mask_candidate) into (c_hi << 32).
         - Hashes step3_candidate with SHA-256 and checks the first 4 bytes.
      5) Stores ALL matches found, and prints them at the end.
*/

// We'll define a struct to hold each match:
struct match_info {
    uint32_t mask_candidate;
    mpz_t    step3;
};

// Compute the first 4 bytes of SHA-256(value) as a 32-bit big-endian integer
static void sha256_first4bytes(const mpz_t value, uint32_t *out_mask)
{
    // Convert mpz_t -> byte array
    size_t byte_count = (mpz_sizeinbase(value, 2) + 7) / 8;
    unsigned char *buf = malloc(byte_count);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }
    mpz_export(buf, NULL, 1, 1, 0, 0, value);

    // Compute SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buf, byte_count, hash);
    free(buf);

    // The mask is the first 4 bytes of the hash as a 32-bit big-endian integer.
    *out_mask = ((uint32_t)hash[0] << 24) |
                ((uint32_t)hash[1] << 16) |
                ((uint32_t)hash[2] <<  8) |
                ((uint32_t)hash[3] <<  0);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ciphertext_in_decimal>\n", argv[0]);
        return 1;
    }

    // Read the ciphertext from argv[1] into a GMP mpz_t
    mpz_t ciphertext;
    mpz_init_set_str(ciphertext, argv[1], 10);

    // We'll define c_hi = ciphertext >> 32, c_lo = ciphertext & 0xffffffff
    mpz_t c_hi, c_lo;
    mpz_inits(c_hi, c_lo, NULL);

    // We need 2^32 in mpz form
    mpz_t two_32;
    mpz_init(two_32);
    mpz_set_ui(two_32, 1UL << 32); // 2^32

    // c_lo = ciphertext mod 2^32
    mpz_set(c_lo, ciphertext);
    mpz_mod(c_lo, c_lo, two_32);

    // c_hi = ciphertext >> 32
    mpz_div_2exp(c_hi, ciphertext, 32);

    // 2) We brute force mask_candidate in [0, 2^32)
    uint64_t limit = (uint64_t)1 << 32;  // 2^32
    printf("[*] Starting brute force up to %llu candidates...\n",
           (unsigned long long)limit);

    // We'll build step3_candidate = (c_hi << 32) + (c_lo XOR mask_candidate).
    mpz_t step3_candidate;
    mpz_init(step3_candidate);

    // Precompute hi_part = c_hi * 2^32
    mpz_t hi_part;
    mpz_init(hi_part);
    mpz_mul(hi_part, c_hi, two_32);

    uint64_t c_lo_val = mpz_get_ui(c_lo);
    uint32_t mask_candidate;

    const uint64_t PRINT_FREQ = 1000000; // print progress every 1 million tries

    // We'll store all matches in a dynamic array 'results'
    struct match_info *results = NULL;
    size_t used = 0;      // how many matches stored
    size_t allocated = 0; // how many slots allocated

    for (mask_candidate = 0; mask_candidate < UINT32_MAX; mask_candidate++) {
        // Show progress
        if ((uint64_t)mask_candidate % PRINT_FREQ == 0) {
            double percent = ((double)mask_candidate / (double)limit) * 100.0;
            printf("[*] Progress: %u / %llu (%.2f%%)\n",
                   mask_candidate,
                   (unsigned long long)limit,
                   percent);
            fflush(stdout);
        }

        // XOR the low 32 bits
        uint64_t xor_val = c_lo_val ^ mask_candidate;

        // step3_candidate = hi_part + xor_val
        mpz_set(step3_candidate, hi_part);
        mpz_add_ui(step3_candidate, step3_candidate, xor_val);

        // Hash step3_candidate => check first 4 bytes
        uint32_t mask_check;
        sha256_first4bytes(step3_candidate, &mask_check);

        if (mask_check == mask_candidate) {
            // We found a match, store it
            // 1) Expand dynamic array if needed
            if (used == allocated) {
                size_t new_alloc = (allocated == 0) ? 16 : (allocated * 2);
                struct match_info *tmp = realloc(results, new_alloc * sizeof(*tmp));
                if (!tmp) {
                    fprintf(stderr, "realloc failed\n");
                    exit(1);
                }
                results = tmp;
                allocated = new_alloc;
            }

            // Initialize mpz, copy the step3_candidate
            mpz_init(results[used].step3);
            mpz_set(results[used].step3, step3_candidate);
            results[used].mask_candidate = mask_candidate;
            used++;
        }
    }

    printf("\n[*] Finished brute force. Found %zu matches.\n", used);

    // Now print them all:
    for (size_t i = 0; i < used; i++) {
        printf("\n[Match #%zu]\n", i+1);
        printf("    mask_candidate = 0x%08X (%u)\n", 
               results[i].mask_candidate, 
               results[i].mask_candidate);
        printf("    step3 = ");
        mpz_out_str(stdout, 10, results[i].step3);
        printf("\n");
    }

    // Clean up
    for (size_t i = 0; i < used; i++) {
        mpz_clear(results[i].step3);
    }
    free(results);

    mpz_clears(ciphertext, c_hi, c_lo, two_32, step3_candidate, hi_part, NULL);
    return 0;
}