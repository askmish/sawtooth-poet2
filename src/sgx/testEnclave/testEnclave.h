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

void loadEnclave();

void test_ecall_Initialize(sgx_enclave_id_t enclaveId,
	                	   sgx_ra_context_t *raContextPtr, 
	 					   poet_err_t *poetErrorPtr);

void test_ecall_CreateErsatzEnclaveReport(sgx_enclave_id_t enclaveId,
                            			  poet_err_t *poetErrorPtr,
                            			  sgx_target_info_t *targetInfoPtr,
                            			  sgx_report_t *enclaveReportPtr);

