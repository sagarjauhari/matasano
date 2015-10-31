# ECB cut-and-paste
# =================
# Write a k=v parsing routine, as if for a structured cookie. The routine should
# take:
#     foo=bar&baz=qux&zap=zazzle
# and produce:
#     {
#       foo: 'bar',
#       baz: 'qux',
#       zap: 'zazzle'
#     }

# (you know, the object; I don't care if you convert it to JSON).
# Now write a function that encodes a user profile in that format, given an
# email address. You should have something like:

#     profile_for("foo@bar.com")

# ... and it should produce:

#     {
#       email: 'foo@bar.com',
#       uid: 10,
#       role: 'user'
#     }

# ... encoded as:

#     email=foo@bar.com&uid=10&role=user

# Your "profile_for" function should not allow encoding metacharacters (& and
# =). Eat them, quote them, whatever you want to do, but don't let people set
# their email address to "foo@bar.com&role=admin".

# Now, two more easy functions. Generate a random AES key, then:
#     A. Encrypt the encoded user profile under the key; "provide" that to the
#     "attacker".
#     B. Decrypt the encoded user profile and parse it.
# Using only the user input to profile_for() (as an oracle to generate "valid"
# ciphertexts) and the ciphertexts themselves, make a role=admin profile.

require "./1-7_aes_ecb.rb"

class ProfileMaker
  def initialize
    # The attacker does not know the key but the same key should be used if the
    # attacker calls 'encrypt_profile' multiple times
    @key = random_str(16)
  end

  # This method is what the attacker can call
  def encrypt_profile(email)
    AES.new.aes_ecb_encrypt(profile_for(email), @key)
  end

  private

  def k_v_parse(str)
    Hash[*str.split("&").map{ |pair| pair.split("=")}.flatten]
  end

  # @return [String] given an email, "email=<email>&uid=10&role=user"
  def profile_for(email)
    safe_str = email.gsub(/[=&]/,"")
    {
      email: safe_str,
      uid: 10,
      role: "user"
    }.map { |k, v| "#{k}=#{v}" }.join("&")
  end
end

# ======= Attacker side ============
# Decrypt an unknown string ecnrypted using ECB by repeatedly calling 
# 'encrypted_profile'

def decrypt_profile
  ap pm.encrypt_profile("a@a.com")
end

def detect_block_size(pm)
  print "Detecting block size: "
  block_size = 0
  # Find out when 2 repeating blocks are found
  (4..50).each do |i|
    aaa = i.times.map{|ii| "A"}.join
    cipher_aaa = pm.encrypt_profile(aaa).unpack("m")[0]

    # Scan cipher text in windows of 2..i/2 to search for repeating blocks
    (2..i/2).each do |win_size|
      # puts "Checking win_size: #{win_size}"
      start_i = 0
      (0..cipher_aaa.length - 2*win_size).each do |start_i|
        block_1 = cipher_aaa[start_i..start_i + win_size-1]
        block_2 = cipher_aaa[start_i + win_size..start_i +(2*win_size - 1)]
        if block_1 == block_2
          block_size = win_size
          break
        end
      end
    end
    if block_size > 0
      puts "*"
      puts "Found block size: #{block_size}"
      break
    end
    print "."
  end

  block_size
end

pm = ProfileMaker.new
detect_block_size(pm)

# cipher64_decrypted = AES.new.aes_ecb_decrypt(cipher64, key)

# ap k_v_parse(cipher64_decrypted.strip)
