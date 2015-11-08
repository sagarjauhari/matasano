# Common helper methods for crypto solutions
require "awesome_print"
require "matrix"

def decode_hex(str)
  [str].pack('H*').bytes
end

def encode_hex(str)
  str.unpack('H*').first
end

def int_arr_to_str(array)
  array.pack('C*')
end

# Counts the number of '1's in the binary format of an integer
def num_one_bits(number)
  number.to_s(2).split("").reduce(0){ |sum, n| sum + n.to_i }
end

def hamming_dist(str1, str2)
  unless str1.length == str2.length
    raise "Strings of different length not supported"
  end

  len = str1.length
  (0..len-1).map do |i|
    num_one_bits(str1[i].ord ^ str2[i].ord)
  end.reduce(&:+)
end

# Tests
unless hamming_dist("this is a test", "wokka wokka!!!") == 37
  raise "Hamming distance incorrect"
end

# @return base64 encoded data without extra line feeds added
def hex_to_base64(str)
  [[str].pack("H*")].pack("m0")
end

############# AES Helpers #############
# Strip PKCS#7 padding if it is valid, else raise exception
def validate_pkcs7(str)
  padding_chars = (1..16).to_a.map(&:chr)
  last_char = str[-1]
  str_stripped = str

  unless padding_chars.include?(last_char)
    raise "PKCS#7 validation failed: Last char not in range 0x01 - 0x0F"
  end

  # If last char is one of the padding chars, then it should repeat exactly
  # as many times
  if ([last_char]*last_char.ord).join == str[-1*(last_char.ord)..-1]
    str_stripped = str[0..-1*(last_char.ord) - 1]
  else
    raise "PKCS#7 validation failed: Padding byte not repeated enough"
  end

  str_stripped
end

# Generate random string of n bytes
def random_str(n_bytes)
  (0..255).to_a.sample(n_bytes).map(&:chr).join
end

# PKCS#7 Padding.
def pad_data(text, block_size)
  # If the original data is a multiple of N bytes, then an extra block of bytes
  # with value N is added.
  n_missing = block_size

  if text.length % block_size > 0
    n_missing = block_size - (text.length % block_size)
  end

  n_missing.times{ text << n_missing.chr }
  text
end

# Pad a block of data with n times with n where n is the difference between
# 'size' and block's current size
def pad_block(block, size)
  n = size - block.length
  block << ([n]*n).pack("C*")
end

# Returns a column major matrix for the array
def array_to_matrix(a)
  Matrix.build(4, 4){ |x, y| a[4*y + x]}
end

# Creates an array assuming matrix is column major
def matrix_to_array(m)
  m.column_vectors.map(&:to_a).flatten
end


# Prints the state
def print_state(state, method_name)
  puts "\tMethod: #{method_name}"
  state.row_vectors.each do |vec|
    puts "\t" + vec.to_a.join("\t")
  end
  puts
end
