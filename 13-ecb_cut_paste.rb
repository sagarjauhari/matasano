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

  def decrypt_profile(cipher_txt)
    k_v_parse(AES.new.aes_ecb_decrypt(cipher_txt, @key))
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
  pm = ProfileMaker.new
  block_size = detect_block_size(pm)

  # I need to generate a block for admin by setting the email and I know that
  # any '=' or '&' in the email will be eaten up. Now the beginning of the
  # encoded string is 6 chars. So, anything in the next 10 chars will be
  # included in the 1st block. After that, whatever I add will be added to the
  # next block. To extract 1 block completely, I need to be able to encode admin
  # in 16chars somehow. 'admin' is 5 chars. 
  cipher =  pm.encrypt_profile("----------admin\0\0\0\0\0\0\0\0\0\0\0").
    unpack("m")[0].strip

  raise "cipher size not a multiple of 16" unless cipher.length % 16 == 0

  block2 = cipher[16..31]

  # This results in no padding:
  #   ap pm.decrypt_profile(pm.encrypt_profile("aaa@g.com"))
  # If I make sure that "user" has its own block, I can swap that block
  # with an ecrypted block of "admin". Since 'user' is 4 bytes I add 4 more chars
  # to the test email:
  #   ap  pm.decrypt_profile(pm.encrypt_profile("aaa4444@g.com"))
  # In the block above, I now just need to swap the last block with the block
  # I extracted above
  cipher2 = pm.encrypt_profile("aaa4444@g.com").unpack("m")[0].strip
  hacked_cipher = [cipher2[0..-17] + block2].pack("m")

  ap pm.decrypt_profile(hacked_cipher)
  # {
  #   "email" => "aaa4444@g.com",
  #     "uid" => "10",
  #    "role" => "admin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # }
end

# Now this is a much better way to detect block size unlike what I did
# in challenge 12.
# Assumptions:
# - encryption mode is ECB. Because only then can we get deterministic cipher
#   block which repeats
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
      return block_size
    end
    print "."
  end

  raise "Block size not detected"
end

decrypt_profile

