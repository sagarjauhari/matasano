require "./helpers.rb"
require "./rijndael_tables.rb"

DEBUG = true

class AES
  Nb =  4 # Number of columns in state
  Nk =  4 # Number of columns in key
  Nr = 10 # Number of rounds

  def initialize
    @state = Matrix[]    # State global var
  end

  def aes_ecb_encrypt(filename, key)
    key_arr = key.unpack("C*")

    File.open(filename, "r") do |file|
      data = pad_data(file.read, 16)[0..127]
      data.unpack("C*").each_slice(16).map do |slice|
        @state = array_to_matrix(slice)

        aes_encrypt_block(key_arr)

        ap matrix_to_array(@state).pack("C*")
      end
    end
  end

  def aes_ecb_decrypt(filename, key)
  end

  private

  # Expands the key to a linear array of 4-byte words of length
  # Nb*(Nr + 1) = 44
  def expand_key(key_arr)
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

  def aes_encrypt_block(key_arr)
    expanded_key = expand_key(key_arr) # generate key for each round

    puts "#{0} - #{Nb - 1}" if DEBUG
    add_round_key(expanded_key[0..(Nb - 1)].flatten)

    (1..Nr - 1).each do |i|
      puts "#{Nb*i} - #{(Nb*(i + 1) - 1)}" if DEBUG
      round(expanded_key[Nb*i..(Nb*(i + 1) - 1)].flatten)
    end

    puts "#{Nb*Nr} - #{(Nb*(Nr + 1) - 1)}" if DEBUG
    round(expanded_key[Nb*Nr..(Nb*(Nr + 1) - 1)].flatten, final: true)
  end

  def round(round_key_arr, final: false)
    sub_bytes
    shift_rows
    mix_cols unless final
    add_round_key(round_key_arr)
  end

  # AES Round 1/4
  def sub_bytes
    @state = @state.map{ |b| S_BOX[b] }
    print_state(__method__) if DEBUG
  end

  # AES inv Round 4/4
  def sub_bytes_inv
      @state = @state.map{ |b| S_BOX_INV[b] }
  end

  # AES Round 2/4
  def shift_rows
    shifted_rows = @state.row_vectors.map.with_index do |vec, idx|
      vec.to_a.rotate(idx)
    end
    @state = Matrix.rows(shifted_rows)
    print_state(__method__) if DEBUG
  end

  # AES inv Round 3/4
  def shift_rows_inv
    col_count = @state.column_count
    shifted_rows = @state.row_vectors.map.with_index do |vec, idx|
      vec.to_a.rotate(col_count - idx)
    end
    @state = Matrix.rows(shifted_rows)
  end

  # AES Round 3/4
  # https://en.wikipedia.org/wiki/Rijndael_mix_columns
  def mix_cols
    mixed_cols = @state.column_vectors.map do |a|
      # 'b' stores each element in 'a' multiplied by 2 in GF(2^8)
      b = a.map{ |val| GALIOS_MUL_2[val] }

      [
        b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1], # 2*a0 + a3 + a2 + 3*a1
        b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2], # 2*a1 + a0 + a3 + 3*a2
        b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3], # 2*a2 + a1 + a0 + 3*a3
        b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]  # 2*a3 + a2 + a1 + 3*a0
      ]
    end
    @state = Matrix.columns(mixed_cols)
    print_state(__method__) if DEBUG
  end

  # AES inv Round 2/4
  def mix_cols_inv
    mixed_cols = @state.column_vectors.map do |a|
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
    @state = Matrix.columns(mixed_cols)
    print_state(__method__) if DEBUG
  end

  # AES Round 4/4
  def add_round_key(round_key_arr)
    @state = @state.map.with_index do |b, idx|
      b ^ round_key_arr[idx]
    end
    print_state(__method__) if DEBUG
  end

  # AES inv Round 1/4 (self inverse)
  def add_round_key_inv(round_key)
    add_round_key(round_key)
  end

  def round_inv(round_key, final: false)
    add_round_key_inv(round_key)
    mix_cols_inv unless final
    shift_rows_inv
    sub_bytes_inv
  end

  def aes_decrypt_block
  end
end

AES.new.aes_ecb_encrypt(
  "1-7_test_plain_text.txt",
  "YELLOW SUBMARINE"
)
