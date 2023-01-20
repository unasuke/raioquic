# Create X25519 kay pair as PEM format it illustrated in RFC 8448.

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import binascii

client_priv_key = x25519.X25519PrivateKey.from_private_bytes(
  binascii.unhexlify("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005")
)

print(client_priv_key.private_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PrivateFormat.PKCS8,
  encryption_algorithm=serialization.NoEncryption()
))

client_pub_key = x25519.X25519PublicKey.from_public_bytes(
  binascii.unhexlify("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c")
)

print(client_pub_key.public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
))

server_priv_key = x25519.X25519PrivateKey.from_private_bytes(
  binascii.unhexlify("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e")
)

print(server_priv_key.private_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PrivateFormat.PKCS8,
  encryption_algorithm=serialization.NoEncryption()
))

server_pub_key = x25519.X25519PublicKey.from_public_bytes(
  binascii.unhexlify("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
)

print(server_pub_key.public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
))
