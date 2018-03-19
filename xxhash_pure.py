import struct

# xxh32
PRIME32_1 = 2654435761
PRIME32_2 = 2246822519
PRIME32_3 = 3266489917
PRIME32_4 =  668265263
PRIME32_5 =  374761393

rotl32 = lambda x, n: (((x << n) & 0xffffffff) | (x >> (32 - n)))
int32le = lambda x: struct.unpack('<I', x)[0]
xxh32_round = lambda a, b: (rotl32((a + b * PRIME32_2) & 0xffffffff, 13) * PRIME32_1) & 0xffffffff

def xxh32_avalance(h32):
    h32 &= 0xffffffff
    h32 ^= (h32 >> 15)
    h32 *= PRIME32_2
    h32 &= 0xffffffff
    h32 ^= (h32 >> 13)
    h32 *= PRIME32_3
    h32 &= 0xffffffff
    h32 ^= (h32 >> 16)
    return h32


class xxh32(object):
    def __init__(self, data='', seed=0):
        self.seed = seed
        self.reset()
        self.update(data)

    def reset(self):
        seed = self.seed
        self.v1 = seed + PRIME32_1 + PRIME32_2
        self.v2 = seed + PRIME32_2
        self.v3 = seed + 0
        self.v4 = seed - PRIME32_1
        self.total_len = 0
        self.mem = bytearray(16)
        self.memsize = 0

    def update(self, data):
        if not data:
            return

        self.total_len += len(data)
        mvdata = memoryview(data)

        if self.memsize + len(mvdata) < 16:
            self.mem[self.memsize:self.memsize+len(mvdata)] = mvdata
            self.memsize += len(mvdata)
            return

        v1, v2, v3, v4 = self.v1, self.v2, self.v3, self.v4

        if self.memsize:
            self.mem[self.memsize:16] = mvdata[:16-self.memsize]
            v1 = xxh32_round(v1, int32le(self.mem[0:4]))
            v2 = xxh32_round(v2, int32le(self.mem[4:8]))
            v3 = xxh32_round(v3, int32le(self.mem[8:12]))
            v4 = xxh32_round(v4, int32le(self.mem[12:16]))
            mvdata = mvdata[16-self.memsize:]
            self.memsize = 0


        i = 0
        while i <= len(mvdata) - 16:
            v1 = xxh32_round(v1, int32le(mvdata[i:i+4]))
            v2 = xxh32_round(v2, int32le(mvdata[i+4:i+8]))
            v3 = xxh32_round(v3, int32le(mvdata[i+8:i+12]))
            v4 = xxh32_round(v4, int32le(mvdata[i+12:i+16]))
            i += 16

        self.memsize = memsize = len(mvdata) - i
        self.mem[:memsize] = mvdata[i:]


        self.v1, self.v2, self.v3, self.v4 = v1, v2, v3, v4

    def intdigest(self):
        v1, v2, v3, v4 = self.v1, self.v2, self.v3, self.v4
        if self.total_len >= 16:
            h32 = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)
        else:
            h32 = v3 + PRIME32_5
        h32 += self.total_len

        i = 0
        while i <= self.memsize - 4:
            h32 += int32le(self.mem[i:i+4]) * PRIME32_3
            h32 &= 0xffffffff
            h32 = rotl32(h32, 17) * PRIME32_4
            i += 4


        for c in self.mem[i:self.memsize]:
            h32 += c * PRIME32_5
            h32 &= 0xffffffff
            h32 = rotl32(h32, 11) * PRIME32_1

        return xxh32_avalance(h32)

    def digest(self):
        return struct.pack('>I', self.intdigest())

    def hexdigest(self):
        return '{:08x}'.format(self.intdigest())

if __name__ == '__main__':
    import xxhash, os, random
    for i in range(4096):
        data = os.urandom(i)
        seed = random.randint(0, 100)
        h1 = xxh32(data, seed).hexdigest()
        h2 = xxhash.xxh32(data, seed).hexdigest()
        assert h1 == h2, (data, seed)
    print('OK')
