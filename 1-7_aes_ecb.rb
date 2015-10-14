require "./helpers.rb"

n_cycles = 10 # Because key is 16 bytes long
state = Matrix[]    # State global var

# AES Round 1/4
def sub_bytes
end

# AES inv Round 4/4
def sub_bytes_inv
end

# AES Round 2/4
def shift_rows
end

# AES inv Round 3/4
def shift_rows_inv
end

# AES Round 3/4
def mix_cols
end

# AES inv Round 2/4
def mix_cols_inv
end

# AES Round 4/4
def add_round_key(round_key)
end

# AES inv Round 1/4
def add_round_key_inv(round_key)
end

def round(round_key, final: false)
  sub_bytes
  shift_rows
  mix_cols unless final
  add_round_key(round_key)
end

def round_inv(round_key, final: false)
  add_round_key_inv(round_key)
  mix_cols_inv unless final
  shift_rows_inv
  sub_bytes_inv
end

def aes_encrypt_block(data_arr, key_arr)
  matrix = array_to_matrix(data_arr)
  data_arr
end

def aes_decrypt_block(data_arr)
end


def aes_ecb_encrypt(filename, key)
  key_arr = key.split("")

  File.open(filename, "r") do |file|
    data = pad_data(file.read, 16)
    data.unpack("C*").each_slice(16).map do |slice|
      ap aes_encrypt_block(slice, key_arr).pack("C*")
    end
  end
end

def aes_ecb_decrypt(filename, key)
end

aes_ecb_encrypt("1-7_test_plain_text.txt", "YELLOW SUBMARINE")
