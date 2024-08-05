import ecdsa
import hashlib
from ecdsa.util import sigdecode_string
import random

curve = ecdsa.NIST192p
hash_func = hashlib.sha1

flag = 0xdeadecd5a
n = curve.order
Ln = n.bit_length()
fixed_k = random.randrange(0, n)

# Generate ECDSA key pair
private_key = ecdsa.SigningKey.from_secret_exponent(secexp=flag, curve=curve, hashfunc=hash_func)
public_key = private_key.verifying_key

def retrieve_vars(signed_message):
  r = signed_message['r']
  s = signed_message['s']
  m = signed_message['message']
  e = int(hash_func(bytes(m, 'utf-8')).hexdigest(), 16)
  z = e >> max(e.bit_length() - Ln, 0)
  return r, s, z

# Function to test whether the private key is recoverable
def private_key_recoverable(signed_messages):
  r1, s1, z1 = retrieve_vars(signed_messages[0])
  _, s2, z2 = retrieve_vars(signed_messages[1])
  
  z_diff = (z1 - z2) % n
  s_diff = (s1 - s2) % n
  s_diff_inv = pow(s_diff, -1, n)
  k = (z_diff * s_diff_inv) % n
  if (k != fixed_k):
    return False
  
  r_inv = pow(r1, -1, n)
  sk = (s1 * k) % n
  dA = (sk - z1) % n
  dA = (dA * r_inv) % n
  
  return flag == dA

# Sign messages with the same k value
msgs = []
for message in ["message1", "message2"]:
  sig = private_key.sign(bytes(message, 'utf-8'), k=fixed_k)
  assert public_key.verify(sig, bytes(message, 'utf-8'))
  r, s = sigdecode_string(sig, private_key.curve.order)
  msgs.append({'message': message,'r': r, 's': s})

assert private_key_recoverable(msgs)

print(f"Curve: 192p")
print(f"Hash function: SHA-1")
print(f"Text encoding: UTF-8\n")

for msg in msgs:
  print(f"m = {msg['message']}")
  print(f"r = {msg['r']}\ns = {msg['s']}\n")