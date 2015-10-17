require "./helpers.rb"

class AES
  def initialize
    @n_cycles = 10       # Because key is 16 bytes long
    @state = Matrix[]    # State global var
  end

  def aes_ecb_encrypt(filename, key)
    key_arr = key.split("")

    File.open(filename, "r") do |file|
      data = pad_data(file.read, 16)[0..127]
      data.unpack("C*").each_slice(16).map do |slice|
        @state = array_to_matrix(slice)

        aes_encrypt_block

        ap matrix_to_array(@state).pack("C*")
      end
    end
  end

  def aes_ecb_decrypt(filename, key)
  end

  private

  def aes_encrypt_block
    round("HELLO")
  end

  def round(round_key, final: false)
    sub_bytes
    shift_rows
    mix_cols unless final
    add_round_key(round_key)
  end

  # AES Round 1/4
  def sub_bytes
    @state = @state.map{ |b| S_BOX[b] }
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
      (c_x * Matrix.columns([vec])).column_vectors.first.to_a
    end
    @state = Matrix.columns(mixed_cols)
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
  def add_round_key(round_key)
  end

  # AES inv Round 1/4
  def add_round_key_inv(round_key)
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
