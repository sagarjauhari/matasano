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
class AES
  def process_file_ctr(action, in_file, key, out_file)
    data = File.open(in_file, "r"){ |f| f.read }
    processed_data = send("aes_ctr_" + action, data, key)

    puts "Writing #{action}ed file (#{processed_data.length} bytes): " +
      "#{out_file}"
    File.open(out_file, "w"){ |f| f.write(processed_data) }
  end
  
  def aes_ctr_encrypt(data, key)
  end

  def aes_ctr_decrypt(data, key)
  end
end

AES.new.process_file_ctr(
  "decrypt",
  "./data/18-data.text",
  "YELLOW SUBMARINE",
  "./dat/18-data_decrypted.txt"
)
