# Implement CBC mode
# ==================
# CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
# messages, despite the fact that a block cipher natively only transforms
# individual blocks.
# In CBC mode, each ciphertext block is added to the next plaintext block before
# the next call to the cipher core.
# The first plaintext block, which has no associated previous ciphertext block,
# is added to a "fake 0th ciphertext block" called the initialization vector, or
# IV.
# Implement CBC mode by hand by taking the ECB function you wrote earlier,
# making it encrypt instead of decrypt (verify this by decrypting whatever you
# encrypt to test), and using your XOR function from the previous exercise to
# combine them.
# The file here is intelligible (somewhat) when CBC decrypted against "YELLOW
# SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c) Don't cheat.
# Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
# What's the point of even doing this stuff if you aren't going to learn from
# it?

require "./1-7_aes_ecb.rb"

class AES
  # @param action [String] "encrypt" or "decrypt"
  # @param iv [String] initiation vector
  def process_file_cbc(action, in_file, key, iv, out_file)
    data = File.open(in_file, "r"){ |f| f.read }
    processed_data = send("aes_cbc_" + action, data, key, iv)

    puts "Writing #{action}ed file (#{processed_data.length} bytes): " +
      "#{out_file}"
    File.open(out_file, "w"){ |f| f.write(processed_data) }
  end

  def aes_cbc_encrypt(data, key, iv)
    key_arr = key.unpack("C*")

    data = pad_data(data, 16)
    last_cipher_block = array_to_matrix(iv) # Initialize with IV
    encrypted_data = data.unpack("C*").each_slice(16).map do |slice|
      state = array_to_matrix(slice)
      
      # XOR the plain text block with last cipher block (or IV if first block)
      state = add_round_key(state, last_cipher_block)

      encrypted_state = aes_encrypt_block(state, key_arr)
      last_cipher_block = encrypted_state # Will be used in next iteration

      matrix_to_array(encrypted_state).pack("C*")
    end

    # return base64 encoded data
    [encrypted_data.join].pack("m")
  end

  def aes_cbc_decrypt(data, key, iv)
    key_arr = key.unpack("C*")

    data = data.unpack("m").first.unpack("C*")
    last_cipher_block = array_to_matrix(iv) # Initialize with IV

    decrypted_data = data.each_slice(16).map do |slice|
      state = array_to_matrix(slice)
      decrypted_state = aes_decrypt_block(state, key_arr)

      # XOR the plain text block with last cipher block (or IV if first block)
      decrypted_state = add_round_key(decrypted_state, last_cipher_block)
      last_cipher_block = state # Will be used in next iteration

      matrix_to_array(decrypted_state).pack("C*")
    end.join

    decrypted_data
  end
end

AES.new.process_file_cbc(
  "decrypt",
  "./data/2-10_data.txt",
  "YELLOW SUBMARINE",
  [0]*16,
  "./data/2-10_data_decrypted.txt"
)
