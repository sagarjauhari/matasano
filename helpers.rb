# Common helper methods for crypto solutions
require "awesome_print"
require "base64"
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
# Pad the plain text if needed to fill blocks of size 'n'
def pad_data(text, block_size)
  n_missing = (text.length % block_size > 0) ? block_size - (text.length % block_size) : 0
  n_missing.times{ text << " " }
  text
end

# Returns a column major matrix for the array
def array_to_matrix(a)
  Matrix.build(4, 4){ |x, y| a[4*y + x]}
end

# Creates an array assuming matrix is column major
def matrix_to_array(m)
  m.column_vectors.map(&:to_a).flatten
end

# Exponentiation of 2 to a user-specified value
AES_RCON = [
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
  0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39
]
