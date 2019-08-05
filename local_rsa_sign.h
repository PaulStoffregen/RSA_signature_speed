
#ifdef __cplusplus
extern "C"{
#endif

int rsa_init(void);
int rsa_sign_string(const char *plaintext, unsigned char *output);

#ifdef __cplusplus
}
#endif

