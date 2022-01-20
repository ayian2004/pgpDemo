from datetime import timedelta
from pgpy.constants import PubKeyAlgorithm, EllipticCurveOID, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

import pgpy

# we start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

#new user id for the key
uid = pgpy.PGPUID.new('Alkiviadis Giannakoulias', comment='MTE2105 user', email='alkiviadis.giannakoulias@ssl-unipi.gr')

# add the new user id to the key
# set the key to expire in 1 year
key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
            key_expires=timedelta(days=365))

# generate a sub key.
subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.NIST_P256)


# protect primary private key with passphrase
key.protect("MT32I0S_P@s$PhrAs3_pkey", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
# protect subkey private key with passphraee
subkey.protect("MT32I0S_P@s$PhrAs3_skey", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

# Ask user for message to encrypt
message = input("Enter your message to encrypt with PGP: ")
# compress message by default with ZIP DEFLATE
message = pgpy.PGPMessage.new(message)

# Encrypt message
# since the key is protected with a passphrase, we will need to unlock it first
with key.unlock("MT32I0S_P@s$PhrAs3_pkey"):
# the bitwise OR operator '|' is used to add a signature to a PGPMessage.
	message |= key.sign(message)
# since the subkey is protected with a passphrase, we will need to unlock it first
	with subkey.unlock("MT32I0S_P@s$PhrAs3_skey"):
		key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})
		subkey.pubkey |= key.certify(subkey.pubkey)
		key.protect("new_P@s$PhrAs3_skey", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        
encrypted_message = subkey.pubkey.encrypt(message)
print(f"\n\nEncrypted message: {encrypted_message}\n")

# Although encryoting  things uses multiple methods, there is only one method to remember for verifying
key.pubkey.verify(message)


# Decrypt message
with key.unlock("new_P@s$PhrAs3_skey"):
	assert key.is_protected
	with subkey.unlock("new_P@s$PhrAs3_skey"):
		assert subkey.is_unlocked
		decrypted_message = subkey.decrypt(encrypted_message)
        
print(f"\n\nDecrypted message verify signature: {key.pubkey.verify(decrypted_message)}")
print(f"\n\nDecrypted message: {decrypted_message.message}\n")
