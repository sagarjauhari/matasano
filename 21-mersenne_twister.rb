# Implement the MT19937 Mersenne Twister RNG
# ==========================================
# You can get the psuedocode for this from Wikipedia.

# If you're writing in Python, Ruby, or (gah) PHP, your language is probably
# already giving you MT19937 as "rand()"; don't use rand(). Write the RNG
# yourself.

def int32(x)
  # Get the 32 least significant bits.
  return 0xFFFFFFFF & x
end

class MersenneTwister
  def initialize(seed)
    # Initialize the index to 0
    @index = 624
    @mt = [0] * 624
    @mt[0] = seed  # Initialize the initial state to the seed
    (1..624).each do |i|
      @mt[i] = int32(
        1812433253 * (@mt[i - 1] ^ @mt[i - 1] >> 30) + i
      )
    end
  end

  def extract_number
    if @index >= 624
      twist
    end

    y = @mt[@index]

    # Right shift by 11 bits
    y = y ^ y >> 11
    # Shift y left by 7 and take the bitwise and of 2636928640
    y = y ^ y << 7 & 2636928640
    # Shift y left by 15 and take the bitwise and of y and 4022730752
    y = y ^ y << 15 & 4022730752
    # Right shift by 18 bits
    y = y ^ y >> 18

    @index += 1

    int32(y)
  end

  def twist
    (0..624).each do |i|
      # Get the most significant bit and add it to the less significant
      # bits of the next number
      y = int32((@mt[i] & 0x80000000) +
                 (@mt[(i + 1) % 624] & 0x7fffffff))
      @mt[i] = @mt[(i + 397) % 624] ^ y >> 1

      if y % 2 != 0
        @mt[i] = @mt[i] ^ 0x9908b0df
      end
    end
    @index = 0
  end
end
