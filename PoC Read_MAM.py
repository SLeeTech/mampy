from iota import Iota
from iota import ProposedTransaction, Address, Tag
from iota import TryteString
from iota.crypto.kerl import Kerl
from iota import Address
from iota import Transaction
import time
import json
import base64
import os
from cryptography.fernet import Fernet
from hashlib import blake2b

print("Enter your Node")
node = input()
api = Iota(node)
print(api.get_node_info())

print("Enter your root address")
input_address = input()
root_address = Address(input_address)


try:
    while True:

        print("Please type in the secret Key:")
        secret_key = input()   

        ## transfroming the secret_key into Base64 Key
        h = blake2b(digest_size=16)
        h_pw = h.update(bytes(secret_key.encode('utf-8')))
        hh = h.hexdigest()
        pw_string = str(hh).encode('utf-8')
        b64_pw = base64.b64encode(pw_string)

        ## find Transaction
        transaction = api.find_transactions(addresses=[root_address])
        txn_hash = transaction['hashes']
        get_txn_bytes = bytes(txn_hash[0])
        get_txn_trytes = api.get_trytes([get_txn_bytes])
        txn_trytes = str(get_txn_trytes['trytes'][0])
        ## Get Transaction Data
        txn = Transaction.from_tryte_string(txn_trytes)
        ## Read Transaction Data
        txn_message = txn.signature_message_fragment.decode()

        print(txn_message)

        ## Decrypt Message
        txn_msg_as_bytes = txn_message.encode('ascii')
        key = b64_pw
        f = Fernet(key)
        decrypt_msg = f.decrypt(txn_msg_as_bytes)

        ## Create json from bytes
        json_string = decrypt_msg.decode("ascii")
        json_file = json.loads(json_string)
        json_data = json_file["message"]
        print(json_data)
        
        ## Create next Root
        astrits = TryteString(str(root_address).encode()).as_trits()
        checksum_trits = []
        sponge = Kerl()
        sponge.absorb(astrits)
        sponge.squeeze(checksum_trits)
        result = TryteString.from_trits(checksum_trits) 
        next_root = result

        print(result)

        root_address = Address(next_root)
        
        time.sleep(3)


except KeyboardInterrupt:
    print("Cleanup")
