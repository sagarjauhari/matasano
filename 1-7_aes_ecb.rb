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
  def process_file(action, in_file, key, out_file)
    data = File.open(in_file, "r"){ |f| f.read }
    processed_data = send("aes_ecb_" + action, data, key)

    puts "Writing #{action}ed file (#{processed_data.length} bytes): " +
      "#{out_file}"
    ap processed_data if DEBUG
    File.open(out_file, "w"){ |f| f.write(processed_data) }
  end

  def aes_ecb_encrypt(data, key)
    key_arr = key.unpack("C*")

    data = pad_data(data, 16)
    encrypted_data = data.unpack("C*").each_slice(16).map do |slice|
      state = array_to_matrix(slice)
      aes_encrypt_block(state, key_arr)
      matrix_to_array(state).pack("C*")
    end

    # return base64 encoded data
    [encrypted_data.join].pack("m")
  end

  def aes_ecb_decrypt(data, key)
    key_arr = key.unpack("C*")

    data = data.unpack("m").first.unpack("C*")
    decrypted_data = data.each_slice(16).map do |slice|
      state = array_to_matrix(slice)
      aes_decrypt_block(state, key_arr)
      matrix_to_array(state).pack("C*")
    end.join

    decrypted_data
  end

  # Expands the key to a linear array of 4-byte words of length
  # Nb*(Nr + 1) = 44
  # @return [[a0, b0, c0, d0], [a1, b1, c1, d1]...[a43, b43, c43, d43] ]
  def key_expansion(key_arr)
    w_key = []
    
    (0..Nk-1).each do |i|
      w_key << key_arr[(4*i)..(4*i + 3)]
    end

    (Nk..(Nb*(Nr + 1) - 1)).each do |i|
      temp = w_key[i-1]
      if i % Nk == 0
        temp = temp.
          rotate.
          map{ |b| S_BOX[b] }.
          map.with_index{ |b, i| b ^ RCON[i / Nk] }
      end

      w_key << w_key[i - Nk].map.with_index{ |b, i| b ^ temp[i]}
    end

    w_key
  end

  # Expands the key to a linear array of 4-byte words of length
  # Nb*(Nr + 1) = 44
  # @return [[a0, b0, c0, d0], [a1, b1, c1, d1]...[a43, b43, c43, d43] ]
  def key_expansion_inv(key_arr)
    expanded_key = key_expansion(key_arr)

    # Apply InvMixColumn to all Round Keys except the first and the last one
    mix_colled = expanded_key[Nb..Nb*Nr-1].each_slice(4).map do |key|
      mix_cols_inv(key)
    end

    expanded_key[0..Nb-1] +
      mix_colled.reduce(&:+) + # Concatenate all keys together into 36 words
      expanded_key[Nb*Nr..Nb*(Nr+1)-1]
  end

  def aes_encrypt_block(state, key_arr)
    expanded_key = key_expansion(key_arr) # generate key for each round

    puts "#{0} - #{Nb - 1}" if DEBUG
    add_round_key(state, expanded_key[0..(Nb - 1)].flatten)

    (1..Nr - 1).each do |i|
      puts "#{Nb*i} - #{(Nb*(i + 1) - 1)}" if DEBUG
      round(state, expanded_key[Nb*i..(Nb*(i + 1) - 1)].flatten)
    end

    puts "#{Nb*Nr} - #{(Nb*(Nr + 1) - 1)}" if DEBUG
    round(state, expanded_key[Nb*Nr..(Nb*(Nr + 1) - 1)].flatten, final: true)
  end

  def aes_decrypt_block(state, key_arr)
    expanded_key = key_expansion_inv(key_arr) # generate key for each inv round
    # TODO Reverse all the words, or reverse all keys keeping order of words
    # intact?
    expanded_key_reverse = expanded_key.reverse

    puts "#{0} - #{Nb - 1}" if DEBUG
    add_round_key(state, expanded_key_reverse[0..(Nb - 1)].flatten)

    (1..Nr - 1).each do |i|
      puts "#{Nb*i} - #{(Nb*(i + 1) - 1)}" if DEBUG
      round_inv(state, expanded_key_reverse[Nb*i..(Nb*(i + 1) - 1)].flatten)
    end

    puts "#{Nb*Nr} - #{(Nb*(Nr + 1) - 1)}" if DEBUG
    round_inv(
      state,
      expanded_key_reverse[Nb*Nr..(Nb*(Nr + 1) - 1)].flatten,
      final: true
    )
  end

  def round(state, round_key_arr, final: false)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_cols(state) unless final
    state = add_round_key(state, round_key_arr)
  end

  def round_inv(state, round_key_arr, final: false)
    state = sub_bytes_inv(state)
    state = shift_rows_inv(state)
    unless final
      state = Matrix.columns(mix_cols_inv(state.column_vectors))
    end
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
    col_count = state.column_count
    shifted_rows = state.row_vectors.map.with_index do |vec, idx|
      vec.to_a.rotate(col_count - idx)
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
  def mix_cols_inv(vectors)
    mixed_cols = vectors.map do |a|
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
    mixed_cols
  end

  # AES Round 4/4 (self inverse)
  def add_round_key(state, round_key_arr)
    # State is column dominant matrix, so the round key arry should also be
    # transposed so that increasing the index in the array corresponds to
    # traversing the state matrix column-wise
    transposed_key_arr =  array_to_matrix(round_key_arr).
      row_vectors.
      map(&:to_a).
      flatten
    state = state.map.with_index do |b, idx|
      b ^ transposed_key_arr[idx]
    end
    print_state(state, __method__) if DEBUG
    state
  end
end

# AES.new.process_file(
#   "encrypt",
#   "1-7_test_plain_text.txt",
#   "YELLOW SUBMARINE",
#   "1-7_test_encrypted.txt"
# )

# AES.new.aes_ecb_decrypt(
#   "1-7_test_encrypted.txt",
#   "YELLOW SUBMARINE",
#   "1-7_test_decrypted.txt"
# )
