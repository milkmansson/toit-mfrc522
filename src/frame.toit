// Copyright (C) 2023 Toitware ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

import nfc.nfc-exception show NfcException

/**
An RFID frame.

Depending on the configuration the frame could be raw (where parity bits must be
  handled by the caller) or not.
*/
class Frame:
  bytes/ByteArray
  size-in-bits/int
  is-raw/bool
  /**
  The position of a collision if there was one.

  Can only happen for frames received by the reader.
  */
  collision-position/int?

  /**
  Constructs a new frame with the given $bytes.

  The $size-in-bits is the number of bits in the frame. It does not need to be a multiple of 8.

  The number of bytes must be at least ($size-in-bits + 7) / 8. In other words, there must be
    enough bits in the given $bytes array.
  */
  constructor .bytes --.size-in-bits=(bytes.size * 8) --raw/bool=false --.collision-position=null:
    is-raw = raw

  /**
  Makes this frame a raw frame, where parity bits are included in the $bytes.

  Adds the parity bits to the frame and sets the $is-raw flag.
  */
  to-raw -> Frame:
    if is-raw: return this
    with-parity := insert-parity-bits_ bytes
    bit-size := bit-size-of-bytes-with-parity_ with-parity
    return Frame with-parity --size-in-bits=bit-size --raw=true

  /**
  Makes this frame a non-raw frame, where parity bits are not included in the $bytes.
  */
  to-non-raw --check-parity -> Frame:
    if not is-raw: return this
    without-parity := remove-parity-bits_ bytes --check=check-parity
    return Frame without-parity

  stringify -> string:
    if collision-position:
      return "Frame($size-in-bits bits: $bytes, collision at $collision-position)"
    if is-raw:
      return "Frame($size-in-bits bits: $bytes, raw)"
    return "Frame($size-in-bits bits: $bytes)"

  /**
  Inserts odd parity bits into the given $bytes.

  The result is a byte array that has an additional parity bit for each byte.
  The valid bits of the result can be computed with $bit-size-of-bytes-with-parity_.
  */
  insert-parity-bits_ bytes/ByteArray -> ByteArray:
    if bytes.size == 0: throw "INVALID_ARGUMENT"

    // Add one parity bit per byte.
    result := ByteArray (bytes.size + (bytes.size + 7) / 8)
    target-index := 0
    target-bit-index := 0
    for i := 0; i < bytes.size; i++:
      byte := bytes[i]
      parity := byte.parity ^ 1  // Odd parity.
      result[target-index] |= byte << target-bit-index
      target-index++
      if target-bit-index != 0:
        result[target-index] |= byte >> (8 - target-bit-index)
      result[target-index] |= parity << target-bit-index
      target-bit-index++
      if target-bit-index == 8:
        target-bit-index = 0
        target-index++
    return result

  bit-size-of-bytes-with-parity_ bytes/ByteArray -> int:
    return (bytes.size * 8 / 9) * 9


  /**
  Removes the parity bits from the given $bytes.

  The result is a byte array that has one less bit for each byte.

  If $check is true then the parity bits are checked and an exception is thrown if they are not
    correct.
  */
  remove-parity-bits_ bytes/ByteArray --check/bool=true -> ByteArray:
    result := ByteArray (bytes.size * 8 / 9)
    source-index := 0
    source-bit-index := 0

    for i := 0; i < result.size; i++:
      byte := bytes[source-index] >> source-bit-index
      source-index++
      if source-bit-index != 0:
        byte |= bytes[source-index] << (8 - source-bit-index)
        byte &= 0xFF
      parity-bit := (bytes[source-index] >> source-bit-index) & 1
      source-bit-index++
      if source-bit-index == 8:
        source-index++
        source-bit-index = 0

      if check:
        parity := byte.parity ^ 1  // Odd parity.
        if parity != parity-bit: throw NfcException.parity

      result[i] = byte
    return result
