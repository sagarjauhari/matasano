# Byte-at-a-time ECB decryption (Harder)
# ======================================
# Take your oracle function from #12. Now generate a random count of random
# bytes and prepend this string to every plaintext. You are now doing:

#  AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

# Same goal: decrypt the target-bytes.

# Stop and think for a second. What's harder than challenge #12 about doing
# this? How would you overcome that obstacle? The hint is: you're using all the
# tools you already have; no crazy math is required. Think "STIMULUS" and
# "RESPONSE".

require "./1-7_aes_ecb.rb"

# Consistent key to be used throughout the run
KEY = random_str(16)

# Consistent random text to be used throughout the run
RANDOM_PLAIN_TXT_MAX_LENGTH = 100
RANDOM_PLAIN_TXT = random_str(rand(10..RANDOM_PLAIN_TXT_MAX_LENGTH))

# AES-128-ECB(random-prefix + attacker-controlled + target-bytes, random-key)
def encrypt_prepend_append(plain_txt, target_bytes64)
  AES.new.aes_ecb_encrypt(
    RANDOM_PLAIN_TXT + plain_txt + target_bytes64.unpack("m")[0],
    KEY
  )
end

# Keep appending increasing length of control bytes till 2 repeating blocks
# are found. Now, do what was done in Problem 12, but assume the first block
# after the repeating blocks as the first block

# This is copied from Chal 13, but modified to interate over a larger increasing
# length of control bytes and also return the position where the repeating block
# is ending - the second repeating block will be used to create the lookup table
# by changing the last byte
# @return [Array<String>] [block_size, block2_start, block2_end]
def detect_block_size
  print "Detecting block size: "
  block_size = 0
  block2_start = 0
  block2_end = 0
  n_target_bytes = 0
  # Find out when 2 repeating blocks are found
  (4..RANDOM_PLAIN_TXT_MAX_LENGTH + 50).each do |i|
    aaa = i.times.map{|ii| "A"}.join
    cipher_aaa = encrypt_prepend_append(aaa, "something").unpack("m")[0]

    # Scan cipher text in windows of 2..i/2 to search for repeating blocks
    (2..i/2).each do |win_size|
      # puts "Checking win_size: #{win_size}"
      start_i = 0
      (0..cipher_aaa.length - 2*win_size).each do |start_i|
        block_1 = cipher_aaa[start_i..start_i + win_size-1]

        block_2 = cipher_aaa[start_i + win_size..start_i +(2*win_size - 1)]
        if block_1 == block_2
          n_target_bytes = i
          block_size = win_size
          block2_start = start_i + win_size
          block2_end = start_i+(2*win_size-1)
          puts "\n2nd block idx: #{block2_start} - #{block2_end}"
          break
        end
      end
    end
    if block_size > 0
      puts "Found block size: #{block_size}"
      return [n_target_bytes, block_size, block2_start, block2_end]
    end
    print "."
  end

  raise "Block size not detected"
end

def decrypt_unknown_str(str_64)
  n_bytes, block_size, start_idx, end_idx = detect_block_size

  # This basically means that the cipher text blocks are like this

  # ----------------------------------------------------------------------------
  # |<- random_txt->|<--------- n-bytes ---------------->|<--- target_bytes -->
  #                    |<- block_size ->|<- block_size ->|
  #                                     |                |
  #                                  start_idx        end_idx
  #
  # Now we need to create a lookup table with plain text set to repeating "As'
  # and the last 'A' replaced by each of the possible 1byte chars
  print "Creating lookup table "
  plain_cipher_dict = (0..255).each_with_object({}) do |i, hash|
    print "."
    spy_block = (["A"]*(n_bytes - 1)).join + i.chr
    cipher_block = encrypt_prepend_append(spy_block, "...").
      unpack("m")[0][start_idx..end_idx]
    hash[cipher_block] = i
  end
  puts

  # Decode the unknown string
  decrypted = str_64.unpack("m")[0].split("").map do |c|
    un_spy_block = (["A"]*(n_bytes - 1)).join + c.chr
    encrypted_un_spy = encrypt_prepend_append(un_spy_block, "...").
      unpack("m")[0][start_idx..end_idx]
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
