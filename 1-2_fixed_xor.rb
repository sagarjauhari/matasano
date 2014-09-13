def fixed_xor(str1, str2)
  (str1.to_i(16) ^ str2.to_i(16)).to_s 16
end