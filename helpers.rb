# Common helper methods for crypto solutions
require "awesome_print"

def decode_hex(str)
  [str].pack('H*').bytes
end

def encode_hex(str)
  str.unpack('H*').first
end

def int_arr_to_str(array)
  array.pack('C*')
end
