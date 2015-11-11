# Break fixed-nonce CTR statistically
# ===================================
# In this file find a similar set of Base64'd plaintext. Do with them exactly
# what you did with the first, but solve the problem differently. Instead of
# making spot guesses at to known plaintext, treat the collection of ciphertexts
# the same way you would repeating-key XOR. Obviously, CTR encryption appears
# different from repeated-key XOR, but with a fixed nonce they are effectively
# the same thing.
#
# To exploit this: take your collection of ciphertexts and truncate them to a
# common length (the length of the smallest ciphertext will work).
#
# Solve the resulting concatenation of ciphertexts as if for repeating- key XOR,
# with a key size of the length of the ciphertext you XOR'd.

# Generate Base64 encoded AES CTR-mode ciphers all using the same keystream

require "./18-aes_ctr.rb"
require "./1-6_break_repeat_key_xor.rb"

def aes_ctr_ciphers
  data = File.readlines("./data/20-data.txt").map{ |line| line.unpack("m")[0]}
  aes = AES.new
  key = random_str(16)

  data.map do |line|
    aes.aes_ctr_encrypt(line, key)
  end
end

def attack_aes_ctr_statistically
  ciphers = aes_ctr_ciphers.map{ |line| line.unpack("m")[0] }

  # Take your collection of ciphertexts and truncate them to a common length
  # (the length of the smallest ciphertext will work).
  min_len = ciphers.map(&:length).min
  puts "Truncating all blocks to size #{min_len}"
  ciphers_truncated = ciphers.map{ |line| line[0..min_len - 1] }

  # TODO Incorrect answer coming
  keystream = break_repeat_key_xor_data(ciphers_truncated.join, min_len)

  decrypted_ciphers = ciphers_truncated.map do |cipher|
    (0..min_len-1).each.map do |idx|
      (cipher[idx].ord ^ keystream[idx].ord).chr
    end.join
  end

  ap decrypted_ciphers
end

# attack_aes_ctr_statistically
