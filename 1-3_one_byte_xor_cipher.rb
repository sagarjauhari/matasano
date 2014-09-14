def single_byte_xor_cipher(str)
  (0...256).map do |i|
    decode_hex(str).map{ |c| (c ^ i) }.pack('C*')
  end
end

def decode_hex(str)
  [str].pack('H*').bytes
end

def encode_hex(str)
  str.unpack('H*').first
end