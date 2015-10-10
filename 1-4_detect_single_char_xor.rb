require "./1-3_one_byte_xor_cipher.rb"
require "awesome_print"

all = File.open("./1-4_data.txt").map do |line|
  print "."
  single_byte_xor_cipher(line).first
end

puts

ap all.sort_by{|i| i[2]}.reverse[0..9]
