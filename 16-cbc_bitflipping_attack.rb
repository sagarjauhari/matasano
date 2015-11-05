# CBC bitflipping attacks
# =======================
# Generate a random AES key. Combine your padding code and CBC code to write two
# functions.
# The first function should take an arbitrary input string, prepend the string:
#     "comment1=cooking%20MCs;userdata="

# .. and append the string:
#     ";comment2=%20like%20a%20pound%20of%20bacon"

# The function should quote out the ";" and "=" characters.
# The function should then pad out the input to the 16-byte AES block length and
# encrypt it under the random AES key.

# The second function should decrypt the string and look for the characters
# ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert
# each resulting string into 2-tuples, and look for the "admin" tuple).

# Return true or false based on whether the string exists.

# If you've written the first function properly, it should not be possible to
# provide user input to it that will generate the string the second function is
# looking for. We'll have to break the crypto to do that.

# Instead, modify the ciphertext (without knowledge of the AES key) to
# accomplish this.

# You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext
# block:
# - Completely scrambles the block the error occurs in
# - Produces the identical 1-bit error(/edit) in the next ciphertext block.
#
# Stop and think for a second.
# Before you implement this attack, answer this question: why does CBC mode have
# this property?

require "./10-cbc_mode.rb"

KEY = random_str(16)
IV  = random_str(16)

def encrypt(str)
  # quote ";" and "="
  str.gsub!(/[=;]/, "-")

  # prepend and append
  str_new = "comment1=cooking%20MCs;userdata=" +
            str +
            ";comment2=%20like%20a%20pound%20of%20bacon"

  # AES automatically pads before encrypting input
  cipher64 = AES.new.aes_cbc_encrypt(str_new, KEY, IV)
end

# @return [Boolean] true if ';admin=true' found, false otherwise
def decrypt(cipher64)
  decrypted = AES.new.aes_cbc_decrypt(cipher64, KEY, IV)
  return decrypted.match(";admin=true") ? true : false
end

def cbc_attack
  # prepended string is 32 bytes => 2 blocks
  block3 = "this is a random"
  # This is carefully crafted so that it can be turned into 'userd;admin=true'
  block4 = "userd-admin-true"

  encrypted = encrypt(block3 + block4).unpack("m")[0]

  # TODO Feels like I'm changing the wrong blocks?
  # Now the 3rd block will be changed so that upon decryption, it alters the
  # 4th block appropriately
  # (";".ord ^ "-".ord).chr => "\x16"
  # ("=".ord ^ "-".ord).chr => "\x10"
  spy_block = encrypted[32..47]
  spy_block[5] = (spy_block[5].ord ^ ";".ord ^ "-".ord).chr
  spy_block[11] = (spy_block[11].ord ^ "=".ord ^ "-".ord).chr

  encrypted = encrypted[0..31] +
              spy_block +
              encrypted[48..-1]

  decrypt([encrypted].pack("m"))
end

puts cbc_attack
