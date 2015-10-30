# Detect AES in ECB mode
# ======================
# In this file are a bunch of hex-encoded ciphertexts. One of them has been
# encrypted with ECB. Detect it. Remember that the problem with ECB is that it
# is stateless and deterministic; the same 16 byte plaintext block will always
# produce the same 16 byte ciphertext.

require "./helpers.rb"

def detect_aes_ecb(filename)
  lines = File.open(filename, "r").map{|l| l}

  blocks = lines.map { |line| line.strip.scan(/.{1,32}/) }

  blocks.map(&:uniq).each_with_index do |l, idx|
    if l.count != 10
      puts "ECB detected at line #{idx + 1} (#{10 - l.count} duplicates)"
      ap lines[idx]
    end
  end
end

# detect_aes_ecb("./data/1-8_data.txt")
