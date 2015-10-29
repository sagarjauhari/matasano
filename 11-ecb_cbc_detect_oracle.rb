# An ECB/CBC detection oracle
# ===========================
# Now that you have ECB and CBC working:

# Write a function to generate a random AES key; that's just 16 random bytes.

# Write a function that encrypts data under an unknown key --- that is, a
# function that generates a random key and encrypts under it.

# The function should look like:

# encryption_oracle(your-input)
# => [MEANINGLESS JIBBER JABBER]

# Under the hood, have the function append 5-10 bytes (count chosen randomly)
# before the plaintext and 5-10 bytes after the plaintext.

# Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC
# the other half (just use random IVs each time for CBC). Use rand(2) to decide
# which to use.

# Detect the block cipher mode the function is using each time. You should end
# up with a piece of code that, pointed at a block box that might be encrypting
# ECB or CBC, tells you which one is happening.

require "./10-cbc_mode.rb"

class AES
  def encryption_oracle(in_file, out_file)
    data = File.open(in_file, "r"){ |f| f.read }
    
    key = random_str(16)          # Generate random key
    iv = random_str(16)           # Generate random IV for CBC mode
    mode = ["ecb", "cbc"].sample  # Choose random mode

    # Append 5-10 bytes of random data before and after the input
    data = (0..255).to_a.sample((5..10).to_a.sample).map(&:chr).join + data
    data = data + (0..255).to_a.sample((5..10).to_a.sample).map(&:chr).join
    
    if mode == "ecb"
      encrypted_data = aes_ecb_encrypt(data, key)
    elsif mode == "cbc"
      encrypted_data = aes_cbc_encrypt(data, key, iv)
    else
      raise "Unknown mode: #{mode}"
    end

    puts "Writing encrypted file (size: #{encrypted_data.length} bytes, mode: " +
    "\"#{mode}\"): #{out_file}"
    File.open(out_file, "w"){ |f| f.write(encrypted_data) }
  end
end

AES.new.encryption_oracle(
  "./data/1-7_test_plain_text.txt",
  "./data/11-test_encrypted_random_mode.txt"
)
