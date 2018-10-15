/*
 Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

#include <iostream>
#include <sstream>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include "sgx_error.h"
#include "../libpoet_shared/poet_defs.h"

#include "poet_enclave_u.h"

#include "testEnclave.h"


sgx_enclave_id_t gEnclaveId;


int main(int argc, char **argv) {

	loadEnclave();

	sgx_ra_context_t raContext;
	poet_err_t poetError = POET_SUCCESS;
	test_ecall_Initialize(gEnclaveId,&raContext,&poetError);

	sgx_target_info_t targetInfo = { 0 };
    sgx_epid_group_id_t gid = { 0 };
    sgx_status_t ret = sgx_init_quote(&targetInfo, &gid);

    sgx_report_t enclaveReport = { 0 };
	test_ecall_CreateErsatzEnclaveReport(gEnclaveId, &poetError,
										&targetInfo, &enclaveReport);


	return 0;

}

void test_ecall_Initialize(sgx_enclave_id_t enclaveId,
	                	   sgx_ra_context_t *raContextPtr, 
	 					   poet_err_t *poetErrorPtr) {


	sgx_status_t ret =  ecall_Initialize(
                                enclaveId,
                                poetErrorPtr,
                                raContextPtr);

	if(ret != SGX_SUCCESS) {
		printf("Error: ecall_Initialize\n");
	} else {
		printf("Success: ecall_Initialize\n");
	}

}

void test_ecall_CreateErsatzEnclaveReport(sgx_enclave_id_t enclaveId,
                            			  poet_err_t *poetErrorPtr,
                            			  sgx_target_info_t *targetInfoPtr,
                            			  sgx_report_t *enclaveReportPtr) {


	sgx_status_t ret =  ecall_CreateErsatzEnclaveReport(
                                enclaveId,
                                poetErrorPtr,
                                targetInfoPtr,
                                enclaveReportPtr);

	if(ret != SGX_SUCCESS) {
		printf("Error: ecall_CreateErsatzEnclaveReport\n");
	} else {
		printf("Success: ecall_CreateErsatzEnclaveReport\n");
	}

}

void loadEnclave() {

    std::string enclaveFilePath = "libpoet_enclave.signed.so";
    sgx_launch_token_t token = { 0 };
    int flags = SGX_DEBUG_FLAG;

    sgx_status_t ret = SGX_SUCCESS;
    int updated = 0;

    ret = sgx_create_enclave(enclaveFilePath.c_str(),
                             flags,
                             &token,
                             &updated,
                             &gEnclaveId,
                             NULL);

    if(ret != SGX_SUCCESS) {
        printf("Error: loadEnclave\n");
    } else {
        printf("Success: loadEnclave\n");
    }
}

extern "C" {

    void ocall_Print(
        const char *str
        )
    {
       
    } 

    void ocall_Log(
        int level,
        const char *str
        )
    {
       
    } 

    void ocall_SetErrorMessage(
        const char* message
        )
    {
        
    }

} // extern "C"

