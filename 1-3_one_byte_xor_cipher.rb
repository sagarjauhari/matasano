require "matrix"

def single_byte_xor_cipher(str)
  strings = (0...256).map do |i|
    decode_hex(str).map{ |c| (c ^ i) }.pack('C*')
  end
  top_ten = sim_scores(strings).sort_by { |k, v| v } .reverse.first(10)
  top_ten.map{|e| [e[0], strings[e[0]], e[1]]}
end

def decode_hex(str)
  [str].pack('H*').bytes
end

def encode_hex(str)
  str.unpack('H*').first
end

# Keep space, apostrophy?
def sim_scores(strings)
  strs = strings.map { |s| s.downcase.gsub(/[^a-z ]+/, '') }
  scores = Hash.new(0)
  strs.each_with_index do |str, i|
    if str == nil || str.length == 0
      scores[i] = 0.0
    else
      scores[i] = cosine_similarity(relative_char_freq(str), en_letter_freq)
    end
  end
  scores
end

def relative_char_freq(str)
  freq_hash = Hash.new(0)
  str.chars.each { |c| freq_hash[c] += 1 }
  freq_hash.keys.each { |k| freq_hash[k] = freq_hash[k].to_f / str.length }
  seq = ('a'..'z').to_a << " "
  seq.map { |k| freq_hash[k] }
end

def cosine_similarity(arr1, arr2)
  v1 = Vector::elements(arr1)
  v2 = Vector::elements(arr2)
  v1.inner_product(v2)/(v1.r * v2.r)
end

def en_letter_freq
  en_occur = {
    'a' => 8167, 'b' => 1492, 'c' => 2782, 'd' => 4253, 'e' => 12702,
    'f' => 2228, 'g' => 2015, 'h' => 6094, 'i' => 6966, 'j' => 153, 'k' => 772,
    'l' => 4025, 'm' => 2406, 'n' => 6749, 'o' => 7507, 'p' => 1929, 'q' => 95,
    'r' => 5987, 's' => 6327, 't' => 9056, 'u' => 2758, 'v' => 978, 'w' => 2360,
    'x' => 150, 'y' => 1974, 'z' => 74,
    ' ' => 12750
  }
  total = en_occur.values.reduce(:+)
  en_occur.keys.each { |k| en_occur[k] = en_occur[k].to_f / total }
  en_occur.values
end

# puts single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")[0][1]
