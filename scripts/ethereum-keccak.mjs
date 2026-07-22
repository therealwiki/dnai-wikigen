const MASK_64 = (1n << 64n) - 1n;

const ROTATION_OFFSETS = Object.freeze([
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
]);

const ROUND_CONSTANTS = Object.freeze([
  0x0000000000000001n, 0x0000000000008082n,
  0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n,
  0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn,
  0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n,
  0x0000000080000001n, 0x8000000080008008n,
]);

function rotateLeft64(value, amount) {
  if (amount === 0) return value & MASK_64;
  const shift = BigInt(amount);
  return ((value << shift) | (value >> (64n - shift))) & MASK_64;
}

function keccakF1600(state) {
  const columns = new Array(5).fill(0n);
  const deltas = new Array(5).fill(0n);
  const moved = new Array(25).fill(0n);
  for (const roundConstant of ROUND_CONSTANTS) {
    for (let x = 0; x < 5; x += 1) {
      columns[x] = state[x] ^ state[x + 5] ^ state[x + 10]
        ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x += 1) {
      deltas[x] = columns[(x + 4) % 5]
        ^ rotateLeft64(columns[(x + 1) % 5], 1);
    }
    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        state[x + 5 * y] = (state[x + 5 * y] ^ deltas[x]) & MASK_64;
      }
    }
    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        const newX = y;
        const newY = (2 * x + 3 * y) % 5;
        moved[newX + 5 * newY] = rotateLeft64(
          state[x + 5 * y],
          ROTATION_OFFSETS[x + 5 * y],
        );
      }
    }
    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        state[x + 5 * y] = (
          moved[x + 5 * y]
          ^ ((~moved[(x + 1) % 5 + 5 * y])
            & moved[(x + 2) % 5 + 5 * y])
        ) & MASK_64;
      }
    }
    state[0] = (state[0] ^ roundConstant) & MASK_64;
  }
}

export function ethereumKeccak256Bytes(value) {
  const bytes = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value);
  const rateBytes = 136;
  const paddedLength = Math.ceil((bytes.length + 1) / rateBytes) * rateBytes;
  const padded = Buffer.alloc(paddedLength);
  bytes.copy(padded);
  padded[bytes.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rateBytes) {
    for (let index = 0; index < rateBytes; index += 1) {
      const lane = Math.floor(index / 8);
      const shift = BigInt((index % 8) * 8);
      state[lane] ^= BigInt(padded[offset + index]) << shift;
    }
    keccakF1600(state);
  }
  const output = Buffer.alloc(32);
  for (let index = 0; index < output.length; index += 1) {
    const lane = state[Math.floor(index / 8)];
    output[index] = Number((lane >> BigInt((index % 8) * 8)) & 0xffn);
  }
  return output;
}

export function ethereumKeccak256Hex(value) {
  return `0x${ethereumKeccak256Bytes(value).toString("hex")}`;
}
