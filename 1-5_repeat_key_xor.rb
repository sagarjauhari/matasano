require "./helpers.rb"

# @return Hex encoded encryped data
def repeat_key_xor(str, key)
  if key.nil? || key.empty?
    raise "Nil key"
  end

  encode_hex(
    int_arr_to_str(
      str.split("").each_with_index.map do |char, i|
        char.ord ^ key[i % key.length].ord
      end
    )
  )
end

# Tests
def run_tests
  [
    [
      "Burning 'em, if you ain't quick and nimble\n"\
      "I go crazy when I hear a cymbal",
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"\
      "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    ]
  ].each_with_index do |test, i|
    result = repeat_key_xor(test[0], "ICE")
    puts "Test #{i}:   #{result == test[1]}"
    unless result == test[1]
      puts "Expected: #{test[1]}"
      puts "Got:      #{result}"
    end
    puts
  end
end

# run_tests
