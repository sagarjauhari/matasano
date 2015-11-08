# Implement CounTeR, the stream cipher mode
# ====================================================
# The string:
#       L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
# ... decrypts to something approximating English in CTR mode, which is an AES
# block cipher mode that turns AES into a stream cipher, with the following
# parameters:
#       key=YELLOW SUBMARINE
#       nonce=0
#       format=64 bit unsigned little endian nonce,
#              64 bit little endian block count (byte count / 16)
# CTR mode is very simple.

# Instead of encrypting the plaintext, CTR mode encrypts a running counter,
# producing a 16 byte block of keystream, which is XOR'd against the plaintext.
# For instance, for the first 16 bytes of a message with these parameters:

# keystream = AES("YELLOW SUBMARINE",
#            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

# ... for the next 16 bytes:
# keystream = AES("YELLOW SUBMARINE",
#            "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")

# ... and then:
# keystream = AES("YELLOW SUBMARINE",
#            "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

# CTR mode does not require padding; when you run out of plaintext, you just
# stop XOR'ing keystream and stop generating keystream.  Decryption is identical
# to encryption. Generate the same keystream, XOR, and recover the plaintext.
# Decrypt the string at the top of this function, then use your CTR function to
# encrypt and decrypt other things.

# Add methods to the existing AES class to do encryption/decryption in
# CTR mode

require "./1-7_aes_ecb.rb"

# Assume:
#   nonce=0
#   format=64 bit unsigned little endian nonce,
#          64 bit little endian block count (byte count / 16)
class AES
  def aes_ctr_encrypt(data, key, params)
    # Following are arrays of byte integers (0-255)
    data_arr = data.unpack("C*")
    encrypted_arr = []
    keystream_arr = []

    data_arr.each_with_index do |data_int, idx|
      block_num = idx / 16
      byte_idx  = idx % 16

      if byte_idx == 0
        # Generate a new keystream block for these 16 bytes
        keystream_arr = new_keystream_arr(block_num, key)
      end

      encrypted_arr << (data_int ^ keystream_arr[byte_idx])
    end

    [encrypted_arr.pack("C*")].pack("m")
  end

  # Almost exactly the same as encryption method
  def aes_ctr_decrypt(cipher64, key, params)
    # Following are arrays of byte integers (0-255)
    cipher_arr = cipher64.unpack("m")[0].unpack("C*")
    decrypted_arr = []
    keystream_arr = []

    cipher_arr.each_with_index do |data_int, idx|
      block_num = idx / 16
      byte_idx  = idx % 16

      if byte_idx == 0
        # Generate a new keystream block for these 16 bytes
        keystream_arr = new_keystream_arr(block_num, key)
      end

      decrypted_arr << (data_int ^ keystream_arr[byte_idx])
    end

    decrypted_arr.pack("C*")
  end

  private

  # @return Array of byte integers (0 - 255)
  def new_keystream_arr(counter, key)
    counter_block = ([0]*8 + [counter] + [0]*7).pack("C*")

    # Unpack and remove 16 byte padding
    aes_ecb_encrypt(counter_block, key).unpack("m")[0].unpack("C*")[0..15]
  end
end

# AES.new.process_file(
#   "ctr",
#   "encrypt",
#   "./data/18-test_plain_text.txt",
#   "YELLOW SUBMARINE",
#   "./data/18-test_encrypted.txt"
# )

AES.new.process_file(
  "ctr",
  "decrypt",
  "./data/18-test_encrypted.txt",
  "YELLOW SUBMARINE",
  "./data/18-test_decrypted.txt"
)
