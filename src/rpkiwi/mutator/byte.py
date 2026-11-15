from __future__ import annotations

import os
import random
from dataclasses import dataclass

@dataclass(frozen=True)
class Mutation:
    name: str
    data: bytes
    description: str

def bit_flip(data: bytes, count: int = 1) -> Mutation:
    if not data:
        return Mutation("bit_flip", data, "empty input")
    buf = bytearray(data)
    positions = []
    for _ in range(count):
        byte_idx = random.randrange(len(buf))
        bit_idx = random.randrange(8)
        buf[byte_idx] ^= 1 << bit_idx
        positions.append(f"{byte_idx}:{bit_idx}")
    return Mutation("bit_flip", bytes(buf), f"flipped {count} bit(s) at {', '.join(positions)}")

def byte_insert(data: bytes, count: int = 1) -> Mutation:
    if not data:
        return Mutation("byte_insert", os.urandom(count), f"inserted {count} byte(s)")
    buf = bytearray(data)
    pos = random.randrange(len(buf) + 1)
    inserted = os.urandom(count)
    buf[pos:pos] = inserted
    return Mutation("byte_insert", bytes(buf), f"inserted {count} byte(s) at offset {pos}")

def byte_delete(data: bytes, count: int = 1) -> Mutation:
    if len(data) <= count:
        return Mutation("byte_delete", b"", "deleted all bytes")
    buf = bytearray(data)
    pos = random.randrange(len(buf) - count + 1)
    del buf[pos:pos + count]
    return Mutation("byte_delete", bytes(buf), f"deleted {count} byte(s) at offset {pos}")

def byte_replace(data: bytes, count: int = 1) -> Mutation:
    if not data:
        return Mutation("byte_replace", data, "empty input")
    buf = bytearray(data)
    pos = random.randrange(max(1, len(buf) - count + 1))
    end = min(pos + count, len(buf))
    buf[pos:end] = os.urandom(end - pos)
    return Mutation("byte_replace", bytes(buf), f"replaced {end - pos} byte(s) at offset {pos}")

def byte_repeat(data: bytes) -> Mutation:
    if len(data) < 2:
        return Mutation("byte_repeat", data, "too short")
    buf = bytearray(data)
    pos = random.randrange(len(buf))
    repeat_count = random.randint(2, 32)
    chunk = bytes([buf[pos]])
    buf[pos:pos + 1] = chunk * repeat_count
    return Mutation("byte_repeat", bytes(buf), f"repeated byte at {pos} x{repeat_count}")

def truncate(data: bytes) -> Mutation:
    if len(data) < 2:
        return Mutation("truncate", b"", "truncated to empty")
    cut = random.randrange(1, len(data))
    return Mutation("truncate", data[:cut], f"truncated at offset {cut}/{len(data)}")

def havoc(data: bytes, rounds: int = 0) -> Mutation:
    if rounds == 0:
        rounds = random.randint(1, 8)
    buf = data
    ops = []
    for _ in range(rounds):
        op = random.choice([bit_flip, byte_insert, byte_delete, byte_replace, byte_repeat, truncate])
        m = op(buf)
        buf = m.data
        ops.append(m.name)
    return Mutation("havoc", buf, f"havoc({rounds}): {' → '.join(ops)}")

ALL_BYTE_MUTATIONS = [
    lambda d: bit_flip(d, random.randint(1, 4)),
    lambda d: byte_insert(d, random.randint(1, 16)),
    lambda d: byte_delete(d, random.randint(1, 8)),
    lambda d: byte_replace(d, random.randint(1, 16)),
    byte_repeat,
    truncate,
    havoc,
]

def mutate_byte(seed: bytes) -> Mutation:
    fn = random.choice(ALL_BYTE_MUTATIONS)
    try:
        return fn(seed)
    except Exception as exc:
        return Mutation("byte_failed", seed, f"mutation failed: {exc}")
