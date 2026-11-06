// Copyright (C) 2023 Toitware ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

class NfcException:
  /**
  Error when a device did not respond.

  This can happen if the user requested to wake a specific device, or if
    the anti-collision protocol selected one of two cards, but none responded at
    the next step.
  */
  static NO-RESPONSE ::= 0

  /** A CRC error was detected. */
  static CRC ::= 1

  /** A parity error was detected. */
  static PARITY ::= 2

  /** A checksum error (BCC, block check character) was detected. */
  static CHECKSUM ::= 3

  /**
  A protocol error was detected.

  A card responded in an unexpected way. Most often, this is actually caused by
    a communication error; for example, when too many cards are in the field.
  */
  static PROTOCOL ::= 4

  /** A timeout was detected. */
  static TIMEOUT-ERROR ::= 5

  /** A collision was detected. */
  static COLLISION ::= 6

  /**
  An internal error was detected.

  If encountered, please file a bug; ideally with a reproducible example.
  */
  static INTERNAL ::= 7

  /**
  The internal temperature sensor detected overheating and shut down the antenna drivers.
  */
  static TEMPERATURE ::= 8

  code/int

  constructor.no-response: code = NO-RESPONSE
  constructor.crc:         code = CRC
  constructor.parity:      code = PARITY
  constructor.checksum:    code = CHECKSUM
  constructor.protocol:    code = PROTOCOL
  constructor.timeout:     code = TIMEOUT-ERROR
  constructor.collision:   code = COLLISION
  constructor.internal:    code = INTERNAL
  constructor.temperature: code = TEMPERATURE

  stringify -> string:
    if code == NO-RESPONSE: return "No response from card"
    if code == CRC: return "CRC error"
    if code == PARITY: return "Parity error"
    if code == CHECKSUM: return "Checksum error (block check character)"
    if code == PROTOCOL: return "Protocol error"
    if code == TIMEOUT-ERROR: return "Timeout"
    if code == COLLISION: return "Collision"
    if code == INTERNAL: return "Internal error"
    if code == TEMPERATURE: return "Temperature error; antenna is off due to overheating"
    unreachable

