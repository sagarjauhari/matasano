# Break repeating-key XOR
# =======================
# It is officially on, now. This challenge isn't conceptually hard, but it
# involves actual error-prone coding. The other challenges in this set are there
# to bring you up to speed. This one is there to qualify you. If you can do this
# one, you're probably just fine up to Set 6.
#
# There's a file here. It's been base64'd after being encrypted with
# repeating-key XOR. Decrypt it. Here's how:
#
# 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say)
# 40.
#
# 2. Write a function to compute the edit distance/Hamming distance between two
# strings. The Hamming distance is just the number of differing bits. The
# distance between: this is a test and wokka wokka!!!  is 37. Make sure your
# code agrees before you proceed.
#
# 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
# KEYSIZE worth of bytes, and find the edit distance between them. Normalize
# this result by dividing by KEYSIZE.
#
# 4. The KEYSIZE with the smallest normalized edit distance is probably the key.
# You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4
# KEYSIZE blocks instead of 2 and average the distances.
#
# 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of
# KEYSIZE length.
#
# 6. Now transpose the blocks: make a block that is the first byte of every
# block, and a block that is the second byte of every block, and so on.
#
# 7. Solve each block as if it was single-character XOR. You already have code
# to do this.
#
# 8. For each block, the single-byte XOR key that produces the best looking
# histogram is the repeating-key XOR key byte for that block. Put them together
# and you have the key.
#
# This code is going to turn out to be surprisingly useful later on. Breaking
# repeating-key XOR ("Vigenere") statistically is obviously an academic
# exercise, a "Crypto 101" thing. But more people "know how" to break it than
# can actually break it, and a similar technique breaks something much more
# important.
#
# No, that's not a mistake. We get more tech support questions for this
# challenge than any of the other ones. We promise, there aren't any blatant
# errors in this text. In particular: the "wokka wokka!!!" edit distance really
# is 37.

require "./helpers.rb"
require "./1-3_one_byte_xor_cipher.rb"
require "./1-5_repeat_key_xor.rb"

def break_repeat_key_xor(filename)
  data64 = File.open(filename).map(&:strip).join("")
  data = data64.unpack("m").first

  # The KEYSIZE with the smallest normalized edit distance is probably the key.
  # You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4
  # KEYSIZE blocks instead of 2 and average the distances.
  best_key_sizes = key_size_stats(data).first(5).map(&:first)
  puts "Following were the best key sizes found: #{best_key_sizes}"

  best_key_sizes.each do |key_size|
    puts "Key size: #{key_size}"
    blocks = transpose_blocks(data, key_size)

    # Solve each block as if it was single-character XOR. For each block, the
    # single-byte XOR key that produces the best looking histogram is the
    # repeating-key XOR key byte for that block. Put them together and you have
    # the key.
    key = blocks.map do |idx, block|
      best_result = single_byte_xor_cipher(encode_hex(block))[0]
      key_part = best_result[0]
      [idx, key_part]
    end.
      sort_by{ |i| i[0] }.
      map{ |i| i[1].chr }.
      join("")

    puts "Probable key: '#{key}'"
    puts "=========================================================="
    puts "Decrypted text: '#{decrypt_64file("./1-6_data.txt", key)}'"
    puts "=========================================================="
  end
end

def key_size_stats(data)
  # Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
  # For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
  # KEYSIZE worth of bytes, and find the edit distance between them. Normalize
  # this result by dividing by KEYSIZE.
  (2..40).each_with_object([]) do |key_size, a|
    dists = data.split("").
      each_slice(2 * key_size).
      with_index.
      select do |slice_arr, i|
        i < (data.length / (2 * key_size))
      end.
      map do |slice_arr, i|
      slice = slice_arr.join
      chunk_1 = slice[0..key_size-1]
      chunk_2 = slice[key_size..2*key_size-1]

      hamming_dist(chunk_1, chunk_2).to_f / key_size
    end

    avg_dist = dists.inject(&:+) / dists.count

    a << [key_size, avg_dist]
  end.sort_by{ |i| i[1] }
end

# Creates blocks of size 'size' and transposes them to create 'size' number
# of new blocks
# For example: transpose_blocks("abcdef", 2)
# => ["ace", "bdf"]
def transpose_blocks(data, size)
  blocks = Hash.new { |h, k| h[k] = [] }

  # Now that you probably know the KEYSIZE: break the ciphertext into blocks of
  # KEYSIZE length.
  data.split("").each_slice(size) do |slice|
    slice.each_with_index do |char, i|
    # Now transpose the blocks: make a block that is the first byte of every
    # block, and a block that is the second byte of every block, and so on.
      blocks[i] << char
    end
  end

  blocks.each do |k, v|
    blocks[k] = v.join("")
  end
end

# Encrypts a data file with repeating key XOR and Base-64s it
# Example:
# encrypt_file("1-6_data_test.txt", "Hello world")
def encrypt_file(filename, key)
  File.open(filename) do |file|
    data = file.read
    encrypted64 = hex_to_base64(repeat_key_xor(data, key))

    File.open("encrypted64_" + filename, "w") do |out_file|
      out_file.write(encrypted64)
    end
  end
end

# Decrypts a Base-64ed file using the key
def decrypt_64file(filename, key)
  data64 = File.open(filename).map(&:strip).join("")
  data = data64.unpack("m").first

  [repeat_key_xor(data, key)].pack("H*")
end


break_repeat_key_xor("./1-6_data.txt")

