from iota import Iota
from iota import ProposedTransaction, Address, Tag
from iota import TryteString
from iota.crypto.kerl import Kerl
from iota import Address
from iota import Transaction
import json
import base64
import os
from cryptography.fernet import Fernet
from hashlib import blake2b





print("Welcome to MAM.py. To Exit use STR+C") 
print("Please enter your Seed")
seed = input()

print("Please enter youre Node")
node = input()

api = Iota(node)

print(api.get_node_info())


print("Create an unused Addrress")
unused_address = api.get_new_addresses(count=None)
root_address = unused_address['addresses'][0]
print(root_address)



try:

    while True:

        print("Create your Message ")
        Message = input()
        print("Create your Tag ")
        TAG = input()
        print("Please type in the secret Key:")
        secret_key = input()     
        

        ## Create next root_address
        astrits = TryteString(str(root_address).encode()).as_trits()
        checksum_trits = []
        sponge = Kerl()
        sponge.absorb(astrits)
        sponge.squeeze(checksum_trits)
        result = TryteString.from_trits(checksum_trits) 
        new_address = Address(result)

        ## transforming the secret_key into Base64 Key
        h = blake2b(digest_size=16)
        h_pw = h.update(bytes(secret_key.encode('utf-8')))
        hh = h.hexdigest()
        pw_string = str(hh).encode('utf-8')
        b64_pw = base64.b64encode(pw_string)

        ## Encrypt the Message
        data = {'message': Message}
        msg = json.dumps(data)
        key = b64_pw
        f = Fernet(key)
        token = f.encrypt(bytes(msg.encode('utf-8')))
        msg_data = token.decode('ascii')


        ## Create a Bundle
        pt = ProposedTransaction(address = root_address,
                                                message = TryteString.from_unicode(msg_data),
                                                tag     = TAG,
                                                value = 0)
        ## Send the Transaction
        FinalBundle = api.send_transfer(depth=3, transfers=[pt], min_weight_magnitude=14)['bundle']

        
        print(new_address)

        root_address = new_address

except KeyboardInterrupt:
    print("Cleanup")



