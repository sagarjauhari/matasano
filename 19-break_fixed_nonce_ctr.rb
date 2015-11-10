# Break fixed-nonce CTR mode using substitions
# ============================================
# Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate
# a random AES key.
# In successive encryptions (not in one big running CTR stream), encrypt each
# line of the base64 decodes in the data file, producing multiple independent
# ciphertexts. (This should produce 40 short CTR-encrypted ciphertexts).
# Because the CTR nonce wasn't randomized for each encryption, each ciphertext
# has been encrypted against the same keystream. This is very bad.
# Understanding that, like most stream ciphers (including RC4, and obviously any
# block cipher run in CTR mode), the actual "encryption" of a byte of data boils
# down to a single XOR operation, it should be plain that:
#
#     CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
#
# And since the keystream is the same for every ciphertext:
#
#     CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't say!")
#
# Attack this cryptosystem piecemeal: guess letters, use expected English
# language frequency to validate guesses, catch common English trigrams, and so
# on. Don't overthink it.  Points for automating this, but part of the reason
# I'm having you do this is that I think this approach is suboptimal.

require "./18-aes_ctr.rb"

# Generates 40 Base64 encoded AES CTR-mode ciphers all using the same keystream
def aes_ctr_ciphers
  data = File.readlines("./data/19-data.txt").map{ |line| line.unpack("m")[0]}
  aes = AES.new
  key = random_str(16)

  data.map do |line|
    aes.aes_ctr_encrypt(line, key)
  end
end

def attack_aes_ctr
  ciphers = aes_ctr_ciphers.map{ |line| line.unpack("m")[0]}

  # TODO Was already thiking of doing what's in the next question.
  # So, skipping this
end

attack_aes_ctr

