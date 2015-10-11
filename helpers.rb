# Common helper methods for crypto solutions
require "awesome_print"
require "base64"

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
