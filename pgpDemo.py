from pgpy.constants import PubKeyAlgorithm, EllipticCurveOID, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from datetime import timedelta
import pgpy

# we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

#new user id for the key
uid = pgpy.PGPUID.new('Spyros Grammatakis', comment='Honest user', email='test@test.com')

# add the new user id to the key
key.add_uid(uid,seflsign=True, usage={KeyFlags.Sign},
            hashes=[HashAlgorithm.SHA256],
	    ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
	    key_expires=timedelta(days=365))

# protect primary private key with passphrase
key.protect("primary", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

# generate a sub key.
subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.NIST_P256)


# protect subkey private key with passphraee
subkey.protect("sub", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

# compressed by default with ZIP DEFLATE
message = pgpy.PGPMessage.new("This is the new message!")

#sign key and message
with key.unlock("primary"):
	sig = key.sign(message)
	message |= key.sign(message)
	with subkey.unlock("sub"):
		key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})
		subkey.pubkey |= key.certify(subkey.pubkey)
		key.protect("key", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

encrypted_message = subkey.pubkey.encrypt(message)
print(encrypted_message)
key.pubkey.verify(message)
with key.unlock("key"):
	assert subkey.is_protected
	with subkey.unlock("key"):
		assert subkey.is_unlocked
		print(message)
		decrypted_message = subkey.decrypt(encrypted_message)
		print(key.pubkey.verify(decrypted_message))
		print(decrypted_message.message)