# AES in ECB mode
# ===============
# The Base64-encoded content in this file has been encrypted via AES-128 in ECB
# mode under the key
# "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW
# SUBMARINE" because it's exactly 16 bytes long, and now you do too).
# Decrypt it. You know the key, after all.
#
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
# Do this with code. You can obviously decrypt this using the OpenSSL
# command-line tool, but we're having you get ECB working in code for a reason.
# You'll need it a lot later on, and not just for attacking ECB.

require "./helpers.rb"
require "./rijndael_tables.rb"

DEBUG = false

class AES
  Nb =  4 # Number of columns in state
  Nk =  4 # Number of columns in key
  Nr = 10 # Number of rounds

  def initialize
    @state = Matrix[]    # State global var
  end

  # @param action "encrypt" or "decrypt"
  def process_file(mode, action, in_file, key, out_file, params: {})
    data = File.open(in_file, "r"){ |f| f.read }
    processed_data = send("aes_#{mode}_#{action}", data, key, params)

    puts "Writing file #{action}ed using AES #{mode} mode " +
      "(#{processed_data.length} bytes): #{out_file}"
    ap processed_data if DEBUG
    File.open(out_file, "w"){ |f| f.write(processed_data) }
  end

  # Encrypts data using AES ECB with key and Base64s it
  def aes_ecb_encrypt(data, key, params)
    key_arr = key.unpack("C*")

    data = pad_data(data, 16)
    encrypted_data = data.unpack("C*").each_slice(16).map do |slice|
      state = array_to_matrix(slice)
      encrypted_state = aes_encrypt_block(state, key_arr)
      matrix_to_array(encrypted_state).pack("C*")
    end

    # return base64 encoded data
    [encrypted_data.join].pack("m")
  end

  # @param data [String] Base64 cipher text
  # @param key [String] Plain text key string
  def aes_ecb_decrypt(data, key, params)
    key_arr = key.unpack("C*")

    data = data.unpack("m").first.unpack("C*")
    decrypted_data = data.each_slice(16).map do |slice|
      state = array_to_matrix(slice)
      decrypted_state = aes_decrypt_block(state, key_arr)
      matrix_to_array(decrypted_state).pack("C*")
    end.join

    decrypted_data
  end

  # Expands the key to a linear array of 4-byte words of length
  # Nb*(Nr + 1) = 44 and then packes them in a matrix
  # @return [Matrix0, Matrix1...Matrix10 ]
  def key_expansion(key_arr)
    w_key = []
    
    (0..Nk-1).each do |i|
      w_key << key_arr[(4*i)..(4*i + 3)]
    end

    (Nk..(Nb*(Nr + 1) - 1)).each do |i|
      temp = w_key[i-1]
      if i % Nk == 0
        temp = temp.rotate.map{ |b| S_BOX[b] }
        temp[0] ^= RCON[i / Nk]
      end

      w_key << w_key[i - Nk].map.with_index{ |b, i| b ^ temp[i]}
    end

    w_key.each_slice(4).map{ |k| array_to_matrix(k.flatten) }
  end

  # Expands the key to a linear array of 4-byte words of length
  # Nb*(Nr + 1) = 44
  # @return [Matrix0, Matrix1...Matrix10 ]
  def key_expansion_inv(key_arr)
    expanded_key = key_expansion(key_arr)

    # Apply InvMixColumn to all Round Keys except the first and the last one
    mix_colled = expanded_key[1..-2].map do |key|
      mix_cols_inv(key)
    end

    [expanded_key[0]] + mix_colled + [expanded_key[-1]]
  end

  def aes_encrypt_block(state, key_arr)
    expanded_key = key_expansion(key_arr) # generate key for each round

    puts "Key 0" if DEBUG
    state = add_round_key(state, expanded_key[0])

    (1..Nr - 1).each do |i|
      puts "Key #{i}" if DEBUG
      state = round(state, expanded_key[i])
    end

    puts "Key #{Nr}" if DEBUG
    state = round(state, expanded_key[Nr], final: true)
  end

  def aes_decrypt_block(state, key_arr)
    expanded_key = key_expansion_inv(key_arr) # generate key for each inv round
    expanded_key_reverse = expanded_key.reverse

    puts "Key 0" if DEBUG
    state = add_round_key(state, expanded_key_reverse[0])

    (1..Nr - 1).each do |i|
      puts "Key #{i}" if DEBUG
      state = round_inv(state, expanded_key_reverse[i])
    end

    puts "Key #{Nr}" if DEBUG
    state = round_inv(state, expanded_key_reverse[Nr], final: true)
  end

  def round(state, round_key, final: false)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_cols(state) unless final
    state = add_round_key(state, round_key)
  end

  def round_inv(state, round_key_arr, final: false)
    state = sub_bytes_inv(state)
    state = shift_rows_inv(state)
    state = mix_cols_inv(state) unless final
    state = add_round_key(state, round_key_arr)
  end

  # AES Round 1/4
  def sub_bytes(state)
    state = state.map{ |b| S_BOX[b] }
    print_state(state, __method__) if DEBUG
    state
  end

  # AES inv Round 4/4
  def sub_bytes_inv(state)
    state = state.map{ |b| S_BOX_INV[b] }
    print_state(state, __method__) if DEBUG
    state
  end

  # AES Round 2/4
  def shift_rows(state)
    shifted_rows = state.row_vectors.map.with_index do |vec, idx|
      vec.to_a.rotate(idx)
    end
    state = Matrix.rows(shifted_rows)
    print_state(state, __method__) if DEBUG
    state
  end

  # AES inv Round 3/4
  def shift_rows_inv(state)
    shifted_rows = state.row_vectors.map.with_index do |vec, idx|
      vec.to_a.rotate(-1*idx)
    end
    state = Matrix.rows(shifted_rows)
    print_state(state, __method__) if DEBUG
    state
  end

  # AES Round 3/4
  # https://en.wikipedia.org/wiki/Rijndael_mix_columns
  def mix_cols(state)
    mixed_cols = state.column_vectors.map do |a|
      # 'b' stores each element in 'a' multiplied by 2 in GF(2^8)
      b = a.map{ |val| GALIOS_MUL_2[val] }

      [
        b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1], # 2*a0 + a3 + a2 + 3*a1
        b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2], # 2*a1 + a0 + a3 + 3*a2
        b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3], # 2*a2 + a1 + a0 + 3*a3
        b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]  # 2*a3 + a2 + a1 + 3*a0
      ]
    end
    state = Matrix.columns(mixed_cols)
    print_state(state, __method__) if DEBUG
    state
  end

  # AES inv Round 2/4. Also used in key_expansion_inv
  # @param vectors Nb vectors: [v_1[a,b,c,d],..v_Nb[w,x,y,z]]
  # @return Nb vectors: [v1[e,f,g,h],..vNb[s,t,u,v]]
  def mix_cols_inv(state)
    mixed_cols = state.column_vectors.map do |a|
      [
        GALIOS_MUL_14[a[0]] ^ GALIOS_MUL_11[a[1]] ^
        GALIOS_MUL_13[a[2]] ^ GALIOS_MUL_9[a[3]],

        GALIOS_MUL_9[a[0]] ^ GALIOS_MUL_14[a[1]] ^
        GALIOS_MUL_11[a[2]] ^ GALIOS_MUL_13[a[3]],

        GALIOS_MUL_13[a[0]] ^ GALIOS_MUL_9[a[1]] ^
        GALIOS_MUL_14[a[2]] ^ GALIOS_MUL_11[a[3]],

        GALIOS_MUL_11[a[0]] ^ GALIOS_MUL_13[a[1]] ^
        GALIOS_MUL_9[a[2]] ^ GALIOS_MUL_14[a[3]]
      ]
    end
    state = Matrix.columns(mixed_cols)
    print_state(state, __method__) if DEBUG
    state
  end

  # AES Round 4/4 (self inverse)
  def add_round_key(state, round_key)
    state = Matrix.build(Nb, Nk) do |row, col|
      state[row, col] ^ round_key[row, col]
    end
    print_state(state, __method__) if DEBUG
    state
  end
end

# AES.new.process_file(
#   "ecb",
#   "encrypt",
#   "data/1-7_test_plain_text.txt",
#   "YELLOW SUBMARINE",
#   "data/1-7_test_encrypted.txt"
# )

# AES.new.process_file(
#   "ecb",
#   "decrypt",
#   "data/1-7_test_encrypted.txt",
#   "YELLOW SUBMARINE",
#   "data/1-7_test_decrypted.txt"
# )

# AES.new.process_file(
#   "ecb",
#   "decrypt",
#   "data/1-7_data.txt",
#   "YELLOW SUBMARINE",
#   "data/1-7_data_decrypted.txt"
# )
