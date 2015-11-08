# The CBC padding oracle
# ======================
# This is the best-known attack on modern block-cipher cryptography. Combine
# your padding code and your CBC code to write two functions.

# The first function should select at random one of the 10 strings in data file
# and generate a random AES key (which it should save for all future
# encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt
# it under that key, providing the caller the ciphertext and IV.

# The second function should consume the ciphertext produced by the first
# function, decrypt it, check its padding, and return true or false depending on
# whether the padding is valid.

# What you're doing here.
# -----------------------
# This pair of functions approximates AES-CBC encryption as its deployed
# serverside in web applications; the second function models the server's
# consumption of an encrypted session token, as if it was a cookie. It turns out
# that it's possible to decrypt the ciphertexts provided by the first function.

# The decryption here depends on a side-channel leak by the decryption function.
# The leak is the error message that the padding is valid or not.

# You can find 100 web pages on how this attack works, so I won't re-explain it.
# What I'll say is this:

# The fundamental insight behind this attack is that the byte 01h is valid
# padding, and occur in 1/256 trials of "randomized" plaintexts produced by
# decrypting a tampered ciphertext.

# - 02h in isolation is not valid padding.
# - 02h 02h is valid padding, but is much less likely to occur randomly than
#   01h.
# - 03h 03h 03h is even less likely.

# So you can assume that if you corrupt a decryption AND it had valid padding,
# you know what that padding byte is. It is easy to get tripped up on the fact
# that CBC plaintexts are "padded". Padding oracles have nothing to do with the
# actual padding on a CBC plaintext. It's an attack that targets a specific bit
# of code that handles decryption. You can mount a padding oracle on any CBC
# block, whether it's padded or not.

require "./10-cbc_mode.rb"

class CBCServer
  def initialize
    @key = random_str(16)
    @iv = random_str(16)
    @aes = AES.new
  end

  # @return [Array<String>] [cipher64, iv]
  def random_cipher_64
    # Read a random line from file and encrypt it
    str = File.readlines("./data/17-data.txt").sample.unpack("m")[0]
    # str = File.readlines("./data/17-data.txt").last.unpack("m")[0]
    [encrypt(str), @iv]
  end

  # Return true/false depending on whether the decrypted text has correct
  # padding
  # @param cipher [String] - binary cipher text
  def decrypt(cipher, iv)
    decrypted = @aes.aes_cbc_decrypt([cipher].pack("m"), @key, iv)

    begin
      validate_pkcs7(decrypted)
    rescue
      return false
    end
    
    return true
  end

  private

  # @return [String] cipher64
  def encrypt(str)
    @aes.aes_cbc_encrypt(str, @key, @iv)
  end
end


# ======== Attacker ========
def padding_attack
  server = CBCServer.new

  cipher, iv = server.random_cipher_64
  cipher = cipher.unpack("m")[0]
  
  final_result = ""
  last_block = iv # initialize last block with IV

  # Iterate over each block
  (0..cipher.length/16 - 1).each do |block_idx|
    block = cipher[block_idx*16..(block_idx + 1)*16 - 1]
    block_decrypted = [0]*16

    # Iterate over each byte starting from the last
    attack_byte_idx_start = 15
    attack_byte_idx_start.downto(0).each do |attack_byte_idx| # debug
      found_byte = false

      (0..255).each do |guessed_byte|
        spy_block = last_block.dup

        # For byte 15, I will overwrite last 1 byte to create \x01
        # For byte 14, I will overwrite last 2 bytes to create \x02\x02
        # For byte 13, I will overwrite last 3 bytes to create \x03\x03\x03
        # For byte  x, I will overwrite last (16-x) bytes to create \x(16-x)...

        # So, first XOR with guessed byte, so that if the guessed byte is
        # correct, plain text at that index should be '0'
        spy_block[attack_byte_idx] = (
          spy_block[attack_byte_idx].ord ^
          guessed_byte
        ).chr

        # Now, XOR all the bytes at the attack byte and after it to
        # 1, 22, 333, 4444 .. depending on index of attack byte
        (attack_byte_idx..15).each do |overwrite_byte_idx|
          spy_block[overwrite_byte_idx] = (
            spy_block[overwrite_byte_idx].ord ^
            (16 - attack_byte_idx)
          ).chr
        end

        if server.decrypt(block, spy_block)
          # Found value!
          block_decrypted[attack_byte_idx] = guessed_byte

          if guessed_byte.ord == 1 && attack_byte_idx == 15
            # Gussing the byte "0x01" is tricky.
            # ----------------------------------
            # If the block is already padded, then if guess byte and target
            # overwrite are both '1', the result would be original string -
            # which returns true since the padding is correct - but the guessed
            # byte will incorrectly be accepted to be 0x01.
            #
            # e.g. plain text block is: "aaaaaaaaaaaaa\03\03\03"
            # Now, when attack byte is the last "\03" and guessed byte is "\01"
            # 3 ^ 1 ^ 1 = 3 (because target overwrite for last byte is 0x01)
            # So, final block would still be "aaaaa\03\03\03" - which is correct
            # padding. Same for "aaaaaaaaaaaa\04\04\04\04"
            #
            # Guessed byte and target overwrite, both being '1' is correct only
            # when the original byte is also '1': "aaaaaaaaaaaaaaa\01". Really?

            next unless last_block[attack_byte_idx].ord == 1
          end

          # puts
          # ap "Found #{guessed_byte.chr}"
          # Handle the case when the plain text is already padded.
          # So, guessed_byte.char is among 0x01 - 0x0F

          # Save the value at attack byte so it can be resued in next iteration
          last_block[attack_byte_idx] = (
            spy_block[attack_byte_idx].ord ^
            (16 - attack_byte_idx)
          ).chr

          found_byte = true
          break
        end
      end

      unless found_byte
        # This probably means that a wrong byte was assumed to be the correct
        # byte in the last index or the 
        puts "\nByte for block #{block_idx} ,idx #{attack_byte_idx} not found!"
        break
      end
    end
    
    final_result << block_decrypted.map(&:chr).join
    last_block = block
    print "."
  end
  puts
  final_result
end

# ap padding_attack
