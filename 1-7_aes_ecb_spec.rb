require "bacon"
require "./1-7_aes_ecb.rb"

describe "AES" do
  before do
    @plain_text = "16 letters long."
    @key = "YELLOW SUBMARINE"
    @state = array_to_matrix(pad_data(@plain_text, 16).unpack("C*"))
    @aes = AES.new

    # encrypted online at http://aesencryption.net
    # using key 'YELLOW SUBMARINE'
    @encrypted_text_64 = "+BSOyLxEcbFQt6U4ZBHN9g=="
  end

  it "ecrypts file correctly" do
    data = @aes.aes_ecb_encrypt(@plain_text, @key)
    data.should.equal @encrypted_text_64
  end

  # it "does correct key expansion" do
  # end

  it "does sub_bytes correctly" do
    matrix = Matrix[[1,2], [14, 15], [254, 255]]
    @aes.sub_bytes(matrix).should.equal(
      Matrix[[0x7c, 0x77], [0xab, 0x76], [0xbb, 0x16]]
    )
  end

  it "does shift_rows correctly" do
    @aes.shift_rows(@state).should.equal(
      Matrix[
        [49, 101, 114, 111],
        [116, 115, 110, 54],
        [32, 103, 32, 116],
        [46, 108, 101, 108]
      ]
    )
  end

  it "does mix_cols correctly" do
    state = Matrix.columns([
      [0xdb, 0x13, 0x53, 0x45],
      [0xf2, 0x0a, 0x22, 0x5c],
      [0x01, 0x01, 0x01, 0x01],
      [0x2d, 0x26, 0x31, 0x4c]
    ])

    @aes.mix_cols(state).should.equal(
      Matrix.columns([
        [0x8e, 0x4d, 0xa1, 0xbc],
        [0x9f, 0xdc, 0x58, 0x9d],
        [0x01, 0x01, 0x01, 0x01],
        [0x4d, 0x7e, 0xbd, 0xf8]
      ])
    )
  end

  it "does add_round_key correctly" do
    state = Matrix.columns([
      [0x01, 0x01, 0x01, 0x01],
      [0xFF, 0x08, 0xFF, 0x08],
      [0x01, 0x01, 0x01, 0x01],
      [0xFF, 0x08, 0xFF, 0x08]
    ])

    key_arr = [
      0x00, 0x01, 0x00, 0x01,
      0xFE, 0xF8, 0xFE, 0xF8,
      0x00, 0x01, 0x00, 0x01,
      0xFE, 0xF8, 0xFE, 0xF8
    ]

    @aes.add_round_key(state, key_arr).should.equal(
      Matrix.columns([
        [0x01, 0x00, 0x01, 0x00],
        [0x01, 0xF0, 0x01, 0xF0],
        [0x01, 0x00, 0x01, 0x00],
        [0x01, 0xF0, 0x01, 0xF0]
      ])
    )
  end

  it "expands key correctly" do
  end
end
