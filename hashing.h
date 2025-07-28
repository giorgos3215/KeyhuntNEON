#ifndef HASHSING
#define HASHSING

int sha256(const unsigned char *data, size_t length, unsigned char *digest);
int rmd160(const unsigned char *data, size_t length, unsigned char *digest);
int keccak(const unsigned char *data, size_t length, unsigned char *digest);
bool sha256_file(const char* file_name, unsigned char * checksum);

int rmd160_4(size_t length, const unsigned char *data0, const unsigned char *data1,
                const unsigned char *data2, const unsigned char *data3,
                unsigned char *digest0, unsigned char *digest1,
                unsigned char *digest2, unsigned char *digest3);

int sha256_4(size_t length, const unsigned char *data0, const unsigned char *data1,
             const unsigned char *data2, const unsigned char *data3,
             unsigned char *digest0, unsigned char *digest1,
             unsigned char *digest2, unsigned char *digest3);

#ifdef __ARM_NEON__
void sha256neon_22(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);
void sha256neon_23(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);
#endif // __ARM_NEON__

#endif // HASHSING