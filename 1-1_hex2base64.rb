def hex_to_base64(str)
  new_str = ""
  while str.length > 0
    a = hex_to_dec(str[0])
    b = hex_to_dec(str[1])
    c = hex_to_dec(str[2])

    new_str << dec_to_base_64((a << 2) + (b >> 2)).to_s
    new_str << dec_to_base_64(((b&3) << 4) + c).to_s
    str = str[3, str.length]
  end
  new_str
end

def hex_to_dec(chr)
  chr.to_i 16
end

def dec_to_base_64(num)
  if num <= 25
    (num + 'A'.ord).chr
  elsif num <= 51
    (num - 26 + 'a'.ord).chr
  elsif num <= 61
    (num - 52 + '0'.ord).chr
  elsif num <= 62
    '+'
  elsif num <= 63
    '//'
  else
    raise 'Number #{num} cannot be greater than 63'
  end
end