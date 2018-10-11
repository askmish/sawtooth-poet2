#include <stdio.h>
#include <stdint.h>

#define MAKE_RUST_SGX_TYPE(sgxtype) typedef struct r_##sgxtype { \
                                        intptr_t handle; \
                                    }r_##sgxtype;

//MAKE_RUST_SGX_TYPE(sgx_signup_info_t);
MAKE_RUST_SGX_TYPE(sgx_enclave_id_t);

typedef struct r_sgx_signup_info_t {
    intptr_t handle;
    char *poet_public_key;
    uint32_t poet_public_key_len;
    //char *proof_data;
    //char *anti_sybil_id;
}r_sgx_signup_info_t;

typedef struct r_sgx_wait_certificate_t {
    intptr_t handle;
	char *serialized_wait_certificate;
	char *serialized_wait_certificate_signature;
}r_sgx_wait_certificate_t;

#ifdef __cplusplus
extern "C" {
#endif

int r_initialize_enclave(r_sgx_enclave_id_t *eid, const char *enclave_path, 
                         const char *spid);

int r_free_enclave(r_sgx_enclave_id_t *eid);

int r_create_signup_info(r_sgx_enclave_id_t *eid, const char *opk_hash, 
                        r_sgx_signup_info_t *signup_info);

int r_release_signup_info(r_sgx_enclave_id_t *eid, r_sgx_signup_info_t *signup_info);

int r_initialize_wait_certificate(r_sgx_enclave_id_t *eid, uint8_t* duration, 
                                    const char* prevCert, const char* prevBlockId, 
                                    const char* validatorId);

int r_finalize_wait_certificate(r_sgx_enclave_id_t* eid, r_sgx_wait_certificate_t* waitCert, 
                                const char* prevBlockId, const char* blockSummary);

int r_release_wait_certificate(r_sgx_enclave_id_t *eid, r_sgx_wait_certificate_t* waitCert);

#ifdef __cplusplus
}
#endif

