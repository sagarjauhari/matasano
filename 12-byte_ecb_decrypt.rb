# Byte-at-a-time ECB decryption (Simple)
# ======================================
# Copy your oracle function to a new function that encrypts buffers under ECB
# mode using a consistent but unknown key (for instance, assign a single random
# key, once, to a global variable).

# Now take that same function and have it append to the plaintext, BEFORE
# ENCRYPTING, the following string:

#     Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
#     aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
#     dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
#     YnkK

# Base64 decode the string before appending it. Do not base64 decode the string
# by hand; make your code do it. The point is that you don't know its contents.
# What you have now is a function that produces:

#     AES-128-ECB(your-string || unknown-string, random-key)

# It turns out: you can decrypt "unknown-string" with repeated calls to the
# oracle function! Here's roughly how:

# 1.  Feed identical bytes of your-string to the function 1 at a time --- start
#     with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block
#     size of the cipher. You know it, but do this step anyway.
# 2.  Detect that the function is using ECB. You already know, but do this step
#     anyways.
# 3.  Knowing the block size, craft an input block that is exactly 1 byte short
#     (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about
#     what the oracle function is going to put in that last byte position.
# 4.  Make a dictionary of every possible last byte by feeding different strings
#     to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC",
#     remembering the first block of each invocation.
# 5.  Match the output of the one-byte-short input to one of the entries in your
#     dictionary. You've now discovered the first byte of unknown-string.
# 6.  Repeat for the next byte.

require "./11-ecb_cbc_detect_oracle.rb"

# Consistent key to be used throughout the run
KEY = random_str(16)

# Appends unknown string (base 64) to plain_text and ECB encrypts it using KEY
def encrypt_after_append(plain_text, str_64)
  str = str_64.unpack("m")[0]
  aes = AES.new
  aes.aes_ecb_encrypt(plain_text + str, KEY)
end

def decrypt_unknown_str(unknown_str)
  # Detect block size:
  # Start with "A" and keep encrypting "AA", "AAA".. and so on. The moment the
  # second half of the cipher text is the same as when "A" was encrypted: the
  # block size is 1 less than that size
  cipher_a = encrypt_after_append("A", "").unpack("m")[0]
  block_size = 0
  print "Detecting block size "
  (2..50).each do |i|
    aaa = i.times.map{|ii| "A"}.join
    cipher_aaa = encrypt_after_append(aaa, "").unpack("m")[0]
    cipher_aaa_2nd_half = cipher_aaa[cipher_aaa.length/2..cipher_aaa.length - 1]
    
    if cipher_a == cipher_aaa_2nd_half
      block_size = i - 1
      print "*"
      break
    end

    print "."
  end
  if block_size == 0
    raise "Could not find ECB Block size"
  else
    puts "\nFound block size: #{block_size}"
  end

  # Detect encryption mode
  aes = AES.new
  aes.decryption_oracle(
    aes.aes_ecb_encrypt(File.read("./data/1-7_test_plain_text.txt"), KEY)
  )

  # Create dictionary for lookup
  plain_cipher_dict = (0..255).each_with_object({}) do |i, hash|
    spy_block = (["A"]*(block_size - 1)).join + i.chr
    hash[aes.aes_ecb_encrypt(spy_block, KEY)] = i
  end

  # Decode the unknown string
  decrypted = unknown_str.unpack("m")[0].split("").map do |c|
    un_spy_block = (["A"]*(block_size - 1)).join + c.chr
    encrypted_un_spy = aes.aes_ecb_encrypt(un_spy_block, KEY)
    plain_cipher_dict[encrypted_un_spy]
  end.map(&:chr).join

  puts decrypted
end

decrypt_unknown_str(
  "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"\
  "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"\
  "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"\
  "YnkK"
)
