require "./helpers.rb"

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
          map.with_index{ |b, i| b ^ AES_RCON[i / Nk] }
      end

      w_key << w_key[i - Nk].map.with_index{ |b, i| b ^ temp[i]}
    end

    w_key
  end

  def aes_encrypt_block(key_arr)
    expanded_key = expand_key(key_arr) # generate key for each round

    puts "#{0} - #{Nb - 1}"
    add_round_key(expanded_key[0..(Nb - 1)].flatten)

    (1..Nr - 1).each do |i|
      puts "#{Nb*i} - #{(Nb*(i + 1) - 1)}"
      round(expanded_key[Nb*i..(Nb*(i + 1) - 1)].flatten)
    end

    puts "#{Nb*Nr} - #{(Nb*(Nr + 1) - 1)}"
    round(expanded_key[Nb*Nr..(Nb(Nr + 1) - 1)].flatten, final: true)
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
  def mix_cols
    c_x = Matrix[
      [0x02 ,0x03 ,0x01, 0x01],
      [0x01 ,0x02 ,0x03, 0x01],
      [0x01 ,0x01 ,0x02, 0x03],
      [0x03 ,0x01 ,0x01, 0x02]
    ]

    mixed_cols = @state.column_vectors.map.with_index do |vec|
      ap c_x * Matrix.columns([vec])
      # this is incorrect. Either replace addition by Xor 
      # or use lookup tables
      (c_x * Matrix.columns([vec])).column_vectors.first.to_a
    end
    @state = Matrix.columns(mixed_cols)
    print_state(__method__) if DEBUG
  end

  # AES inv Round 2/4
  def mix_cols_inv
    d_x = Matrix[
      [0x0b, 0x0d, 0x09, 0x0e],
      [0x0e, 0x0b, 0x0d, 0x09],
      [0x09, 0x0e, 0x0b, 0x0d],
      [0x0d, 0x09, 0x0e, 0x0b],
    ]

    mixed_cols = @state.column_vectors.map.with_index do |vec|
      (d_x * Matrix.columns([vec])).column_vectors.first.to_a
    end
    @state = Matrix.columns(mixed_cols)
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
