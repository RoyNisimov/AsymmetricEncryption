import math
def Log2(x):
    if x == 0:
        return False

    return (math.log10(x) /
            math.log10(2))

# Function to check
# if x is power of 2


def isPowerOfTwo(n):
    return (math.ceil(Log2(n)) ==
            math.floor(Log2(n)))