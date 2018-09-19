class SignUpInfo:
        def __init__(self,poet_public_key,proof_data,anti_sybil_id,nonce):
                self.poet_public_key = poet_public_key
                self.proof_data = proof_data
                self.anti_sybil_id = anti_sybil_id
                self.nonce = nonce
        
class ValidatorInfo:
        def __init__(self,name,id,signup_info,txn_id):
                self.name = name
                self.id = id
                self.signup_info = signup_info
                self.txn_id = txn_id

class ValidatorRegistryPayload:
        def __init__(self,verb,name,id,signup_info):
                self.verb = verb
                self.name = name
                self.id = id
                self.signup_info = signup_info

