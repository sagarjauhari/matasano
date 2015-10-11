require "./helpers.rb"
require "./1-3_one_byte_xor_cipher.rb"
require "./1-5_repeat_key_xor.rb"

def break_repeat_key_xor(filename)
  data64 = File.open(filename).map(&:strip).join("")
  data = data64.unpack("m").first

  ap repeat_key_xor(data, "Hello world")

  # The KEYSIZE with the smallest normalized edit distance is probably the key.
  # You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4
  # KEYSIZE blocks instead of 2 and average the distances.
  best_key_sizes = key_size_stats(data).first(10).map(&:first)
  puts "Following were the best key sizes found: #{best_key_sizes}"

  best_key_sizes = [11] # debug

  best_key_sizes.each do |key_size|
    puts "Key size: #{key_size}"
    blocks = transpose_blocks(data, key_size)

    # Solve each block as if it was single-character XOR. For each block, the
    # single-byte XOR key that produces the best looking histogram is the
    # repeating-key XOR key byte for that block. Put them together and you have
    # the key.
    key = blocks.map do |idx, block|
      ap block
      ap idx
      raise "hello"
      best_result = single_byte_xor_cipher(block, debug: true)[0]
      ap best_result

      key_part = best_result[0]
      [idx, key_part]
    end.
      sort_by{ |i| i[0] }.
      map{ |i| i[1].chr }.
      join("")

    ap key
  end
end

def key_size_stats(data)
  # Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
  # For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
  # KEYSIZE worth of bytes, and find the edit distance between them. Normalize
  # this result by dividing by KEYSIZE.
  (2..40).each_with_object([]) do |key_size, a|
    chunk_1 = data[0..key_size-1]
    chunk_2 = data[key_size..2*key_size-1]

    a << [key_size, hamming_dist(chunk_1, chunk_2).to_f / key_size]
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

# break_repeat_key_xor("./1-6_data.txt")

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


# break_repeat_key_xor("./1-6_data_test_encrypted64.txt")

