// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

/**
A driver for the MFRC522 RFID reader.
*/

import serial
import .crypto1
import .frame
import .nfc-exception

class Mfrc522:
  static COMMAND-REGISTER_ ::= 0x01 << 1
  static COM-IRQ-REGISTER_ ::= 0x04 << 1
  static ERROR-REGISTER_ ::= 0x06 << 1
  static STATUS-2-REGISTER_ ::= 0x08 << 1
  static FIFO-DATA-REGISTER_ ::= 0x09 << 1
  static FIFO-LEVEL-REGISTER_ ::= 0x0A << 1
  static CONTROL-REGISTER_ ::= 0x0C << 1
  static BIT-FRAMING-REGISTER_ ::= 0x0D << 1
  static COLL-REGISTER_ ::= 0x0E << 1
  static MODE-REGISTER_ ::= 0x11 << 1
  static TX-MODE-REGISTER_ ::= 0x12 << 1
  static RX-MODE-REGISTER_ ::= 0x13 << 1
  static TX-CONTROL-REGISTER_ ::= 0x14 << 1
  static TX-ASK-REGISTER_ ::= 0x15 << 1
  static MF-RX-REGISTER_ ::= 0x1D << 1
  static MOD-WIDTH-REGISTER_ ::= 0x24 << 1
  static T-MODE-REGISTER_ ::= 0x2A << 1
  static T-PRESCALER-REGISTER_ ::= 0x2B << 1
  static T-RELOAD-REGISTER_ ::= 0x2C << 1
  static AUTO-TEST-REGISTER_ ::= 0x36 << 1
  static VERSION-REGISTER_ ::= 0x37 << 1

  static COMMAND-IDLE_ ::= 0x00                // No action, cancels current command
  static COMMAND-MEM_ ::= 0x01                 // Stores 25 bytes into the internal buffer.
  static COMMAND-GENERATE-RANDOM-ID_ ::= 0x02  // Generates a 10-byte random ID number.
  static COMMAND-CALCULATE-CRC_ ::= 0x03       // Activates the CRC coprocessor or performs a self test.
  static COMMAND-TRANSMIT_ ::= 0x04            // Transmits data from the FIFO buffer.
  static COMMAND-NO-CMD-CHANGE_ ::= 0x07       // No command change. Can be used to modify the other bits without affecting the command.
  static COMMAND-RECEIVE_ ::= 0x08             // Activates the receiver circuits.
  static COMMAND-TRANSCEIVE_ ::= 0x0C          // Transmits data from FIFO buffer to antenna and automatically activates the receiver after transmission.
  static COMMAND-MF-AUTHENT_ ::= 0x0E          // Performs the MIFARE standard authentication as a reader.
  static COMMAND-SOFT-RESET_ ::= 0x0F          // Resets the MFRC522.

  registers_ /serial.Registers

  current-framing_ /int? := null
  current-parity_ /int? := null

  crypto_ /MifareCryptoReader? := null

  constructor device/serial.Device:
    registers_ = device.registers

  on:
    reset-soft_
    reset-communication_

    // When communicating with a card we need a timeout if something goes wrong.
    // f_timer = 13.56 MHz / (2 * pre_scaler + 1).
    // We pre_scale by a factor of 169, giving us a scaled frequency of ~40kHz, and a timer period of ~25us.
    pre-scaler := 0x0A9
    // Start the timer automatically at the end of a transmission all communication modes at all speeds.
    // The least significant bits store the pre_scaler's high bits.
    t-mode := 0x80 | (pre-scaler >> 8)
    registers_.write-u8 T-MODE-REGISTER_ t-mode
    // The remaining pre_scaler bits are stored in the T_PRESCALER_REGISTER.
    registers_.write-u8 T-PRESCALER-REGISTER_ (pre-scaler & 0xFF)
    reload-ticks := 1000  // Timeout of 1000 * 25us = 25ms.
    registers_.write-u16-be T-RELOAD-REGISTER_ reload-ticks

    // Force a 100% ASK modulation independent of the ModWidth setting.
    // ASK = Amplitude Shift Keying.
    // This is copied from https://github.com/miguelbalboa/rfid/blob/b2ff919438c2c2924092de8348b19049359dddd0/src/MFRC522.cpp#L239
    // Default: 0x00
    registers_.write-u8 TX-ASK-REGISTER_ 0x40

    // Set the CRC coprocessor parameter to using 0x6363 as CRC preset value.
    // See section 6.1.6 CRC_A of the ISO_IEC_14443-3:2001 specification.
    // Section 9.3.2.2.
    // Default value: 0x3F.
    // CRC-Presets: bits 0-1, with 0b01 setting it to 0x6363.
    registers_.write-u8 MODE-REGISTER_ 0x3D

    // A soft reset turns the antennas off.
    antenna-on

  /**
  Transmits a short frame and returns the response.

  A short frame consists of just 7 bits of data. It doesn't have any CRC or parity bit.

  Common short-frame commands:
  - REQA (0x26): Request any new card to go into IDLE state.
  - WUPA (0x52): Requests any card to go into IDLE state.

  Other values:
  - 0x35: Optional timeslot method. (see Annex C of iso14443-3)
  - 0x40 to 0x4F: Proprietary.
  - 0x78 to 0x7F: Proprietary.
  - all other values: RFU (reserved for future use).

  See section Iso 14443-3 2008; section 6.2.3.1.
  */
  transceive-short_ command/int --allow-collision/bool -> Frame?:
    if command >= 0x80: throw "INVALID_ARGUMENT"

    frame := Frame #[command] --size-in-bits=7
    // Since the frame is short, we don't need to worry about enabling or
    // disabling the parity.
    return transceive_ frame --allow-collision=allow-collision

  /**
  Transmits a standard frame and returns the response.

  If $check-crc is true, then automatically checks the crc of the response.
  If $add-crc is true, then automatically adds the CRC to the $bytes. This is almost
    always the correct choice. The only exception is when the reader is authenticating
    a Mifare card.

  If $crypto_ is not null then uses it to encrypt the data.
  */
  transceive-standard_ bytes/ByteArray --check-crc/bool=false --add-crc/bool=true -> Frame?:
    if add-crc:
      crc := compute-crc_ bytes
      bytes += #[crc & 0xFF, (crc >> 8) & 0xFF]

    result-frame/Frame? := ?
    if crypto_:
      frame := crypto_.encrypt bytes
      result-frame = transceive_ frame
      if result-frame:
        decrypted := crypto_.decrypt result-frame
        result-frame = Frame decrypted
    else:
      frame := Frame bytes
      result-frame = transceive_ frame

    if not result-frame: return null

    if not check-crc: return result-frame

    assert: not result-frame.collision-position
    assert: result-frame.bytes.size * 8 == result-frame.size-in-bits
    check-crc_ result-frame.bytes
    return Frame result-frame.bytes[..result-frame.bytes.size - 2]

  /**
  Transmits an anticollision frame and returns the response.

  An anticollision frame might have only some bits of the last byte that are valid. During
    sending only those last bits are used. During receiving the first bits are shifted as to
    complete the byte.

  The $last-byte-bits parameter specifies how many bits of the last byte are valid. It must
    be between 1 and 8.

  The response is automatically shifted, so that it would complete the last byte.
  */
  transceive-anticollision_ bytes/ByteArray --last-byte-bits/int -> Frame?:
    frame := Frame bytes --size-in-bits=((bytes.size - 1) * 8 + last-byte-bits)

    // When receiving, the first bit should be shifted by 'rx_align', so that the
    // original bytes and the new bits align.
    shift := (last-byte-bits % 8)
    return transceive_ frame --allow-collision --shift-response-by=shift

  /**
  Sets the framing for future transmissions.

  The $rx-align parameter is used for handling collisions. It should otherwise always be 0.
    The first received bit is shifted by $rx-align positions. For example, if it is 6, then the
    first 2 received bits are stored as MSB bits of the first byte, and the remaining received bits
    are stored in subsequent bytes.

  The $tx-last-bits parameter defines the number of bits of the last byte that should be transmitted.
    If it is equal to 0, then the whole byte is transmitted. This value is 7 for short frames (since
    they have only 7 data bits), 0 for standard frames, and any value for anticollision frames.
  */
  set-framing_ --rx-align/int=0 --tx-last-bits/int=0:
    if not 0 <= rx-align < 8: throw "INVALID_ARGUMENT"
    if not 0 <= tx-last-bits < 8: throw "INVALID_ARGUMENT"

    // Bit 7: StartSend == 0. (If 1, starts the transmission of data; only valid in
    //     combination with the Transceive command).
    // Bit 6-4: RxAlign. Used for reception of bit-oriented frames.
    //    Usually 0, except for bitwise anticollision at 106bBd.
    //    0: LSB of the received bit is stored at bit position 0; second at position 1.
    //    1: LSB of the received bit is stored at bit position 1; second at position 2.
    //    7: LSB of the received bit is stored at bit position 7; the second received bit is
    //        stored in the next byte that follows a bit position 0.
    // Bit 3: reserved for future use.
    // Bit 2-0: TxLastBits. Used for transmission of bit oriented frames: defines the number of
    //     bits of the last byte that will be transmitted. 0 indicates that all bits should be transmitted.
    framing-value := (rx-align << 4) | tx-last-bits
    if framing-value == current-framing_: return

    current-framing_ = null
    registers_.write-u8 BIT-FRAMING-REGISTER_ framing-value
    current-framing_ = framing-value

  enable-parity_:
    // Section 9.3.2.14.
    // Bit 4 disables the generation and checking of parity.
    value := 0x00
    if current-parity_ == value: return

    current-parity_ = null
    registers_.write-u8 MF-RX-REGISTER_ value
    current-parity_ = value

  disable-parity_:
    // Section 9.3.2.14.
    // Bit 4 disables the generation and checking of parity.
    value := 0x10
    if current-parity_ == value: return

    current-parity_ = null
    registers_.write-u8 MF-RX-REGISTER_ value
    current-parity_ = value

  /**
  Transmits the given $frame to the card and waits for a response.

  If $allow-collision is false, then throws if a collision is detected. Otherwise, stores
    the position of the collision in the result. Note that the position of the
    collision is affected by the $shift-response-by parameter.

  When receiving, the first bit is shifted by $shift-response-by positions. This is used
    for anticollision frames, where the first bits are shifted to complete the last byte.
    The synthentic bits are set to 0 and are counted as if sent by the card. As such, the
    position of the collision is affected by this parameter.

  The $shift-response-by also impacts parity checking. If $shift-response-by is non-zero,
    the reader expects a parity bit after 8 - $shift-response-by bits. It ignores this
    bit.
  */
  transceive_ frame/Frame -> Frame?
      --command/int=COMMAND-TRANSCEIVE_  // Can also be $COMMAND_MFAUTHENT_.
      --allow-collision/bool=false
      --shift-response-by/int=0:

    if frame.is-raw:
      disable-parity_
    else:
      enable-parity_

    // The FIFO can handle up to 64 bytes.
    if frame.bytes.size > 64: throw "INVALID_ARGUMENT"

    // Cancel any existing command.
    registers_.write-u8 COMMAND-REGISTER_ COMMAND-IDLE_

    // Clear all irq bits.
    // The MSB of the register is 0, indicating that all marked bits are cleared.
    registers_.write-u8 COM-IRQ-REGISTER_ 0x7F

    // Flush the FIFO buffer.
    // "Immediately clears the internal FIFO buffer's read and write pointer and ErrorReg register's BufferOvfl bit."
    registers_.write-u8 FIFO-LEVEL-REGISTER_ 0x80

    // Set the framing.
    set-framing_ --rx-align=shift-response-by --tx-last-bits=(frame.size-in-bits % 8)

    // Write the data into the FIFO.
    registers_.write-bytes FIFO-DATA-REGISTER_ frame.bytes

    // Send the command.
    registers_.write-u8 COMMAND-REGISTER_ command

    if command == COMMAND-TRANSCEIVE_:
      // Execute the transceive.
      // 9.3.1.14:
      //   Bit 7: StartSend: If 1, starts the transmission of data; only valid in
      //       combination with the Transceive command.
      registers_.write-u8 BIT-FRAMING-REGISTER_ (registers_.read-u8 BIT-FRAMING-REGISTER_) | 0x80

    // Wait for the response:
    completed := false
    // TODO(florian): make sure timing is correct.
    for i := 0; i < 10; i++:
      irqs := registers_.read-u8 COM-IRQ-REGISTER_
      // Irq bits:
      // 7: Set1. When writing defines whether the masked bits should be set or cleared.
      // 6: TxIRq. Set immediately after the last bit of the transmitted data was sent out.
      // 5: RxIRq. Receiver has detected the end of a valid data stream. Note: RxModeReg can influence behavior.
      // 4: IdleIRq. If a command terminates, for example, when the CommandReq changes its value
      //    from any command to the Idle command. If an unknown command is started.
      //    The microcontroller starting the Idle command does not set the IdleIRq bit.
      // 3: HiAlertIRq. Status1Reg has HiAlert bit set.
      // 2. LoAlertIRq. Status1Reg has LoAlert bit set.
      // 1. ErrIRq. any error bit in the ErrorReg register is set.
      // 0. TimerIRq: the timer decrements the timer value in register TCounterValReg to zero.

      // Rx and Idle. (Not sure why idle).
      if irqs & 0x30 != 0:
        completed = true
        break
      // Timeout. Remember that we automatically start the timeout due to the initialization
      // in the $on function.
      if (irqs & 0x01) != 0:
        throw NfcException.timeout
      sleep --ms=3

    if not completed: return null

    error := registers_.read-u8 ERROR-REGISTER_
    /*
    Section 9.3.1.7. Table 34.
    * Bit 7 - WrErr: data is written into the FIFO buffer by the host at an invalid point in time.
    * Bit 6 - TempErr: internal temperature sensor detects overheating, in which case the antenna drivers are
        automatically turned off.
    * Bit 5 - reserved.
    * Bit 4 - BufferOvfl: the host (or the MFRC522's internal state machine) tries to write data into to
        FIFO even though it's already full.
    * Bit 3 - CollErr: collision error. The MFRC522's internal state machine detected a collision.
    * Bit 2 - CRCErr: CRC error. The CRC check of the received data failed.
    * Bit 1 - ParityErr: parity error. The received data has an invalid parity.
    * Bit 0 - ProtocolErr: SOF is incorrect. (Used for MFAuthent).
    */

    detected-collision := error & 0x08 != 0
    if detected-collision and not allow-collision:
      throw NfcException.collision

    collision-position/int? := ?
    if not detected-collision:
      collision-position = null
    else:
      // Ignore parity errors. They might be caused by the collision.
      error &= ~0x02

      collision-value := registers_.read-u8 COLL-REGISTER_

      // C code clears bits received after a collision.
      // Don't think we need that.
      // PCD_ClearRegisterBitMask(CollReg, 0x80);
      // registers_.write_u8 COLL_REGISTER_ (collision_value & 0x7F)

      has-valid-collision-position := (collision-value & 0x20) == 0
      if not has-valid-collision-position:
        // Collision detected, but without any valid position.
        throw NfcException.internal

      collision-position = collision-value & 0x1F
      // If the collision position is 0, then the collision happened at bit 32.
      // See MFRC522 - 9.3.1.15, table 50.
      if collision-position == 0: collision-position = 32

    // For bit 7 and 4 something is writing even though it shouldn't.
    if error & 0x80 != 0 or error & 0x10 != 0: throw NfcException.internal
    if error & 0x40 != 0:                      throw NfcException.temperature
    if error & 0x04 != 0:                      throw NfcException.crc
    if error & 0x02 != 0:                      throw NfcException.parity
    if error & 0x01 != 0:                      throw NfcException.protocol

    response-size := registers_.read-u8 FIFO-LEVEL-REGISTER_
    // We must not use `read_bytes` for SPI. That doesn't yield the correct result.
    result-bytes := ByteArray response-size: registers_.read-u8 FIFO-DATA-REGISTER_

    // TODO(florian): read the last-byte bits.
    result-frame := Frame result-bytes
        --collision-position=collision-position
        --size-in-bits=(response-size * 8)
        --raw=frame.is-raw

    return result-frame

  /**
  Computes the CRC as required by the ISO 14443-3 standard.

  The chip actually has a hardware based CRC, but it's almost certainly faster to just do it here.
  */
  compute-crc_ data/ByteArray -> int:
    // Specification 6.2.4 CRC_A.
    // Also see Appendix B.
    // Initial register shall be 0x6363.
    // The polynomial is from ISO/IEC 13239: 0x8408
    crc := 0x6363
    data.size.repeat:
      crc = crc ^ data[it]
      8.repeat:
        if (crc & 1) != 0:
          crc = (crc >> 1) ^ 0x8408
        else:
          crc >>= 1
    return crc

  check-crc_ data/ByteArray:
    if data.size < 3: throw NfcException.protocol
    crc := compute-crc_ data[..data.size - 2]
    if crc & 0xFF != data[data.size - 2] or crc >> 8 != data[data.size - 1]:
      throw NfcException.crc

  /**
  Executes an anticollision to get the UID of a PICC in the field.

  The cascade-level is encoded in the $command.
  The $uid-buffer must be 4 bytes long and correspond to the current cascade level.

  Returns when the $uid-buffer is filled.
  */
  cascade-get-uid_ command/int uid-buffer/ByteArray -> none:
      assert: uid-buffer.size == 4

      known-bits := 0

      // Complete this cascade level.
      // That is, iterate until we have a unique UID for this cascade level.
      // We might iterate this loop 32 times because of a collision for each bit.
      while true:
        index := 0
        // The biggest outbound frame consists of 6 bytes:
        // - 1 byte command.
        // - 1 byte valid bytes/bits.
        // - 4 bytes of UID (potentially the first one being a Cascade Tag, indicating that the UID needs
        //          an additional cascade level).
        bytes := ByteArray 6
        bytes[index++] = command

        // Fully valid uid bytes.
        valid-uid-bytes := known-bits / 8
        // Additional valid bits.
        valid-bits := known-bits % 8

        // The valid bits are encoded with the higher nible containing the amount of fully valid bytes, and the
        // the lower nibble containing the remaining bits.
        // The encoded value includes the select-command and the valid-bits byte.
        // If this is a full select (all bits are known), the value is updated below.
        encoded-valid-bits := ((valid-uid-bytes + 2) << 4) + valid-bits
        bytes[index++] = encoded-valid-bits

        last-byte-bits/int := ?
        to-copy/int := ?
        if valid-bits == 0:
          last-byte-bits = 8
          to-copy = valid-uid-bytes
        else:
          last-byte-bits = valid-bits
          to-copy = valid-uid-bytes + 1

        for i := 0; i < to-copy; i++:
          bytes[index++] = uid-buffer[i]

        // Request the PICCs to complete the ID and watch for collisions.
        response-frame := transceive-anticollision_ bytes[..index] --last-byte-bits=last-byte-bits
        if not response-frame: throw NfcException.no-response

        response := response-frame.bytes

        // The PICC is supposed to complete the UID and add a checksum (BCC).
        if response.size + valid-uid-bytes != 5:
          throw NfcException.protocol

        // We start by assuming that the response is without collision. If there was one, we will
        // fix that later.
        uid-pos := valid-uid-bytes
        response-index := 0
        if valid-bits != 0:
          half-byte := response[response-index]
          uid-buffer[uid-pos] &= (1 << valid-bits) - 1  // Clear the bits that were unknown.
          uid-buffer[uid-pos] |= half-byte
          uid-pos++
          response-index++
        while uid-pos < 4:
          uid-buffer[uid-pos++] = response[response-index++]

        detected-collision := response-frame.collision-position != null
        if not detected-collision:
          bcc := uid-buffer[0] ^ uid-buffer[1] ^ uid-buffer[2] ^ uid-buffer[3]
          if bcc != response[response-index]: throw NfcException.checksum
          return

        collision-position := response-frame.collision-position
        if collision-position <= known-bits: throw "STATE_ERROR"
        if collision-position + known-bits > 32: throw "STATE_ERROR"
        // Up to the collision position the bits were received correctly.
        // At the collision point we now have to choose which branch we want to follow.
        // We arbitrarily pick the one that we already wrote into the uid_buffer, and just
        // state that this bit is now a known bit.
        known-bits += collision-position

  /**
  Transceives the select for this cascade level.

  Returns the received SAK (select acknowledge).
  */
  cascade-select_ command/int uid-buffer/ByteArray -> ByteArray:
    // The frame frame consists of 9 bytes:
    // - 1 byte command.
    // - 1 byte valid bytes/bits. Since all bits are valid, always equal to 0x70.
    // - 4 bytes of UID (potentially the first one being a Cascade Tag, indicating that the UID needs
    //          an additional cascade level).
    // - 1 byte of BCC (Block Check Character).
    // - 2 bytes of CRC. These will be added by the `transceive_standard_` function.
    bytes := ByteArray 7

    bytes[0] = command

    // 7 bytes, since we also send the BCC.
    // The CRC is not counted.
    bytes[1] = 0x70

    bytes.replace 2 uid-buffer

    // We know all bits for this level.
    // This is a "select" call, and not an anti-collision frame.
    // A select also needs the BCC and the CRC.
    bcc := bytes[2] ^ bytes[3] ^ bytes[4] ^ bytes[5]
    bytes[6] = bcc
    response-frame := transceive-standard_ bytes --check-crc

    if not response-frame: throw NfcException.no-response

    response := response-frame.bytes
    // The SAK must be exactly 1 bytes long (once the CRC has been removed).
    if response.size != 1: throw NfcException.protocol
    return response

  /**
  Selects one of the woken PICCs.

  PICCs can be woken either by sending a REQA or WUPA. See $(do --new [block]) and $with-picc.
  */
  select_ uid/ByteArray=#[] -> Card:
    // Section 6.5.3.1
    // A UID is either 4, 7, or 10 bytes long.
    // A cascade level has only space for 4 bytes of payload.
    // If the UID is 4 bytes long, we can just send it in the first cascade.
    // If it's longer, we use the cascade tag as first byte of the payload to
    // indicate that another cascade level follows. The same is true for the second cascade level.
    // If it's 7 bytes long, we already sent 3 bytes in the first cascade, and can use the remaining
    // 4 bytes for the rest. Otherwise, we send again a cascade tag, followed by the next 3 bytes.
    //
    // Note that the cascade tag is not a valid byte at 0'th and 4'th position to avoid ambiguity.
    //
    // When sending a select command we send as much of the UID as we already know. All
    // PICCs that fit the (partial) UID respond with the rest of the UID. The PCD then detects
    // collisions, and we arbitrarily pick one of the colliding PICCs.
    // Over time we end up increasing the amount of known bits.
    CASCADE-TAG ::= 0x88

    SELECT-CASCADE1 ::= 0x93  // 4 byte UID.
    SELECT-CASCADE2 ::= 0x95  // 7 byte UID.
    SELECT-CASCADE3 ::= 0x97  // 10 byte UID.

    // Create a uid-buffer which represents more closely what we actually send.
    // If we don't have any UID, also make sure we have space to write for the received data.
    uid-buffer/ByteArray := ?
    if uid.size == 0: uid-buffer = ByteArray 12
    else if uid.size == 4: uid-buffer = uid
    else if uid.size == 7: uid-buffer = #[CASCADE-TAG] + uid
    else if uid.size == 10:
      uid-buffer = #[CASCADE-TAG] + uid[0..3] + #[CASCADE-TAG] + uid[3..]
    else:
      throw "INVALID_ARGUMENT"

    // We can now send the chunks nicely, 4 bytes each.
    assert: uid-buffer.size % 4 == 0

    // The known bits, including cascade tags, of the UID.
    known-bits := uid.size == 0 ? 0 : uid-buffer.size * 8

    // Go through the different cascade levels.
    // If the ID is shorter we break out of the loop.
    for cascade-level := 1; cascade-level <= 3; cascade-level++:
      command /int := ?
      if cascade-level == 1: command = SELECT-CASCADE1
      else if cascade-level == 2: command = SELECT-CASCADE2
      else: command = SELECT-CASCADE3

      cascade-uid-buffer := uid-buffer[(cascade-level - 1) * 4 .. cascade-level * 4]

      // Unless we already have the UID, perform an anticollision to get one UID in the field.
      if uid.size == 0:
        cascade-get-uid_ command cascade-uid-buffer

      // Select acknowledge.
      sak := cascade-select_ command cascade-uid-buffer

      // 6.5.3.4: if b3 is set then the UID is not complete.
      needs-another-cascade := sak[0] & 0x04 != 0

      if needs-another-cascade:
        if cascade-level == 3: throw NfcException.protocol
        continue

      // Remove the cascade tags.
      if cascade-level == 1: uid = uid-buffer[0..4].copy
      else if cascade-level == 2: uid = uid-buffer[1..8].copy
      else: uid = uid-buffer[1..4] + uid-buffer[5..]

      return Card this uid sak[0]

    unreachable
/*
  is_authenticated_ -> bool:
    // Section 9.3.1.9.
    // Bit 3: MFCrypto1On. Indicates that the MIFARE Crypto1 unit is switched on.
    return (registers_.read_u8 STATUS_2_REGISTER_) & 0x08 != 0

  authenticate_ --block/int --key/ByteArray --uid/ByteArray --is_key_a/bool -> bool:
    if uid.size != 4 and uid.size != 7 and uid.size != 10: throw "INVALID_ARGUMENT"
    if key.size != 6: throw "INVALID_ARGUMENT"

    // See MIFARE Classic EV1 1K spec.
    // https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf
    // Section 9.1.
    AUTHENT_KEY_A_COMMAND ::= 0x60
    AUTHENT_KEY_B_COMMAND ::= 0x61

    // Section 10.3.1.9. MFAuthent of MFRC522 datasheet.
    // 12 bytes need to be written into the FIFO:
    // - Authentication command code (60h, 61h), selecting key A or B.
    // - Block address
    // - 6 sector key bytes.
    // - 4 card serial number bytes.
    bytes := ByteArray 12
    bytes[0] = is_key_a ? AUTHENT_KEY_A_COMMAND : AUTHENT_KEY_B_COMMAND
    bytes[1] = block
    bytes.replace 2 key
    // Fill in the last 4 bytes of the UID.
    // See section 3.2.5 of AN10927.
    // See section 10.1.3 of MIFARE Classic EV1 1K spec.
    bytes.replace 8 uid[uid.size - 4  ..]

    frame := Frame bytes
    result := transceive_ --command=COMMAND_MF_AUTHENT_ frame
    return result != null

  stop_crypto_:
    // Section 9.3.1.9.
    // Bit 3: MFCrypto1On. When this bit is cleared then the crypto1 is turned off.
    old := registers_.read_u8 STATUS_2_REGISTER_
    registers_.write_u8 STATUS_2_REGISTER_ (old & ~0x08)
*/

  is-authenticated_ -> bool:
    return crypto_ != null

  authenticate_ --block/int --key/ByteArray --uid/ByteArray --is-key-a/bool -> bool:
    successful := false
    try:
      if uid.size != 4 and uid.size != 7 and uid.size != 10: throw "INVALID_ARGUMENT"
      if key.size != 6: throw "INVALID_ARGUMENT"

      // See MIFARE Classic EV1 1K spec.
      // https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf
      // Section 9.1.
      AUTHENT-KEY-A-COMMAND ::= 0x60
      AUTHENT-KEY-B-COMMAND ::= 0x61

      // TODO(florian): apparently we need to decrypt the nonce tag with the new
      // crypto1. Currently it's encrypted with the old one.
      // See crypto1.toit main: the last examples there are decoded correctly.

      is-nested := crypto_ != null

      if not crypto_:
        crypto_ = MifareCryptoReader --uid=uid

      crypto_.start-authentication --key=key

      nonce-tag-frame := transceive-standard_ --no-check-crc #[
            is-key-a ? AUTHENT-KEY-A-COMMAND : AUTHENT-KEY-B-COMMAND,
            block,
          ]

      if not nonce-tag-frame:
        print "no nonce tag"
        return false

      nonce-tag := nonce-tag-frame.bytes

      // In theory this should be a random number.
      nonce-reader := #[ 0x00, 0x00, 0x00, 0x00 ]

      sleep --ms=10
      challenge-response := crypto_.generate-challenge-response
          --nonce-tag=nonce-tag
          --nonce-reader=nonce-reader

      tag-response-frame := transceive-standard_
          --no-add-crc
          --no-check-crc
          challenge-response

      if not tag-response-frame:
        print "no tag response frame"
        return false

      successful = crypto_.compare-tag-response tag-response-frame.bytes
      return successful
    finally:
      // Make sure we don't leave the crypto in a bad state.
      // If we are not successful, then the communication is pretty much
      // broken anyway.
      if not successful:
        crypto_ = null

  stop-crypto_:
    crypto_ = null

  wake-up-cards_ --only-new/bool=false -> Frame?:
    reset-communication_

    // Wake up the given PICC.
    // ISO 14443-3
    CMD-WUPA ::= 0x52
    // Wake up new cards.
    // The CMD_REQA should be sent in a "short frame" which has only 7 bits.
    // Iso-14443-3, 6.4.1. "The REQA and WUPA commands [..] are transmitted within a short frame".
    CMD-REQA ::= 0x26

    command := only-new ? CMD-REQA : CMD-WUPA

    // The CMD_REQA/CMD_WUPA should be sent in a "short frame" which has only 7 bits.
    // Iso-14443-3, 6.4.1. "The REQA and WUPA commands [..] are transmitted within a short frame".
    return transceive-short_ command --allow-collision

  /**
  Wakes up all new PICCs and executes the given $block for each.

  The $block is called with the UID of the PICC as argument.
  */
  do --new/bool [block] -> none:
    if not new: throw "INVALID_ARGUMENT"

    while true:
      if not wake-up-cards_ --only-new: return
      card := select_
      try:
        block.call card
      finally:
        card.close

  /**
  Wakes up all cards and selects the card with the given $uid. Then executes the given $block.

  The $block is called with the $Card as argument.
  */
  with-picc uid/ByteArray [block] -> none:
    if not wake-up-cards_: return
    card := select_ uid
    try:
      block.call card
    finally:
      card.close

  antenna-on:
    current := registers_.read-u8 TX-CONTROL-REGISTER_
    if current & 0x03 == 0x03: return
    registers_.write-u8 TX-CONTROL-REGISTER_ (current | 0x03)

  antenna-off:
    current := registers_.read-u8 TX-CONTROL-REGISTER_
    if current & 0x03 != 0x03: return
    registers_.write-u8 TX-CONTROL-REGISTER_ (current & ~0x03)

  reset-soft_:
    registers_.write-u8 COMMAND-REGISTER_ COMMAND-SOFT-RESET_
    // The datasheet doesn't say how long the soft reset takes.
    // The MFRC522 might have been in soft power-down mode, which would take 1024 clock cycles until the
    // mode is exited. In theory we should be able to observe this by looking at the command register. Also,
    // when waking up from this mode, we must take into account that the oscillator takes time to become
    // stable (see the remark in section 8.6.2).
    // According to section 8.8, the oscillator start-up time is the startup-time of the crystal + 37.74us.
    sleep --ms=50
    // Make sure that we are not still waking up from soft power-down mode.
    count := 0
    COMMAND-STATUS-POWER-DOWN-BIT_ ::= 0x10
    while count++ < 3 and (registers_.read-u8 COMMAND-REGISTER_) & COMMAND-STATUS-POWER-DOWN-BIT_ != 0:
      sleep --ms=50

  /**
  Resets the communication configuration.

  Some cards can communicate at different speeds, and might have changed the configurations.
  Resets the baud rate and modulation width to their default values.
  */
  reset-communication_:
    // Reset baud rates.
    registers_.write-u8 TX-MODE-REGISTER_ 0x00
    registers_.write-u8 RX-MODE-REGISTER_ 0x00
    // Reset ModWidthReg.
    registers_.write-u8 MOD-WIDTH-REGISTER_ 0x26

    // Section 9.3.1.9.
    // Bit 3: MFCrypto1On. When this bit is cleared then the crypto1 is turned off.
    old := registers_.read-u8 STATUS-2-REGISTER_
    registers_.write-u8 STATUS-2-REGISTER_ (old & ~0x08)

  /**
  Performs a self test.

  Checks that the self-test data corresponds to one of the $accepted $SelfTestData values.
  */
  self-test --accepted/List=[ SelfTestData.MFRC522-V0-0, SelfTestData.MFRC522-V1-0, SelfTestData.MFRC522-V2-0, SelfTestData.FM17522 ]:
    // Follows the steps outlined in the datasheet, section 16.1.1.

    // 1. Soft Reset
    reset-soft_

    // 2. Clear the buffers and commit to memory.
    zeroes := ByteArray 25: 0x00
    // Clear the fifo.
    registers_.write-u8 FIFO-LEVEL-REGISTER_ 0x80
    registers_.write-bytes FIFO-DATA-REGISTER_ zeroes
    registers_.write-u8 COMMAND-REGISTER_ COMMAND-MEM_

    // 3. Enable the self test by writing 09h to the AutoTestReg register.
    registers_.write-u8 AUTO-TEST-REGISTER_ 0x09

    // 4. Write 00h to FIFO buffer.
    registers_.write-u8 FIFO-DATA-REGISTER_ 0x00

    // 5. Start self test with the CalcCRC command.
    registers_.write-u8 COMMAND-REGISTER_ COMMAND-CALCULATE-CRC_

    // 6. The self test is initiated.
    // 7. When the self test has completed, the FIFO buffer contains the following 64 bytes:

    for i := 0; i < 10; i++:
      level := registers_.read-u8 FIFO-LEVEL-REGISTER_
      if level == 64: break
      sleep --ms=100

    // Stop the CRC command.
    registers_.write-u8 COMMAND-REGISTER_ COMMAND-IDLE_

    // Read out the 64 bytes from the FIFO buffer.
    bytes := ByteArray 64: registers_.read-u8 FIFO-DATA-REGISTER_

    // Reset the AUTO_TEST_REGISTER_ to 0, so normal operation can resume.
    registers_.write-u8 AUTO-TEST-REGISTER_ 0x00
    version := registers_.read-u8 VERSION-REGISTER_

    accepted.do:
      self-test-data/SelfTestData := it
      if version == self-test-data.version and bytes == self-test-data.bytes: return

    throw "Self test failed; unknown self-test data: $version $bytes"

/**
Firmware data for self-tests.
*/
class SelfTestData:

  /**
  Self-test data for MFRC522, version 0.0.

  Version 0.0 (0x90)
  Philips Semiconductors; Preliminary Specification Revision 2.0 - 01 August 2005; 16.1 self-test.
  Copied from: https://github.com/miguelbalboa/rfid/blob/b2ff919438c2c2924092de8348b19049359dddd0/src/MFRC522.h#L31
  */
  static MFRC522-V0-0 ::= SelfTestData 0x90
    #[
      0x00, 0x87, 0x98, 0x0f, 0x49, 0xFF, 0x07, 0x19,
      0xBF, 0x22, 0x30, 0x49, 0x59, 0x63, 0xAD, 0xCA,
      0x7F, 0xE3, 0x4E, 0x03, 0x5C, 0x4E, 0x49, 0x50,
      0x47, 0x9A, 0x37, 0x61, 0xE7, 0xE2, 0xC6, 0x2E,
      0x75, 0x5A, 0xED, 0x04, 0x3D, 0x02, 0x4B, 0x78,
      0x32, 0xFF, 0x58, 0x3B, 0x7C, 0xE9, 0x00, 0x94,
      0xB4, 0x4A, 0x59, 0x5B, 0xFD, 0xC9, 0x29, 0xDF,
      0x35, 0x96, 0x98, 0x9E, 0x4F, 0x30, 0x32, 0x8D,
    ]

  /**
  Self-test data for MFRC522, version 1.0.

  Version 1.0 (0x91)
  MFRC522, Product data sheet, rev. 3.9 - 27 April 2016; 16.1.1 self-test.
  */
  static MFRC522-V1-0 ::= SelfTestData 0x91
    #[
      0x00, 0xC6, 0x37, 0xD5, 0x32, 0xB7, 0x57, 0x5C,
      0xC2, 0xD8, 0x7C, 0x4D, 0xD9, 0x70, 0xC7, 0x73,
      0x10, 0xE6, 0xD2, 0xAA, 0x5E, 0xA1, 0x3E, 0x5A,
      0x14, 0xAF, 0x30, 0x61, 0xC9, 0x70, 0xDB, 0x2E,
      0x64, 0x22, 0x72, 0xB5, 0xBD, 0x65, 0xF4, 0xEC,
      0x22, 0xBC, 0xD3, 0x72, 0x35, 0xCD, 0xAA, 0x41,
      0x1F, 0xA7, 0xF3, 0x53, 0x14, 0xDE, 0x7E, 0x02,
      0xD9, 0x0F, 0xB5, 0x5E, 0x25, 0x1D, 0x29, 0x79,
    ]

  /**
  Self-test data for MFRC522, version 2.0.

  Version 2.0 (0x92)
  MFRC522, Product data sheet, rev. 3.9 - 27 April 2016; 16.1.1 self-test.
  */
  static MFRC522-V2-0 ::= SelfTestData 0x92
    #[
      0x00, 0xEB, 0x66, 0xBA, 0x57, 0xBF, 0x23, 0x95,
      0xD0, 0xE3, 0x0D, 0x3D, 0x27, 0x89, 0x5C, 0xDE,
      0x9D, 0x3B, 0xA7, 0x00, 0x21, 0x5B, 0x89, 0x82,
      0x51, 0x3A, 0xEB, 0x02, 0x0C, 0xA5, 0x00, 0x49,
      0x7C, 0x84, 0x4D, 0xB3, 0xCC, 0xD2, 0x1B, 0x81,
      0x5D, 0x48, 0x76, 0xD5, 0x71, 0x61, 0x21, 0xA9,
      0x86, 0x96, 0x83, 0x38, 0xCF, 0x9D, 0x5B, 0x6D,
      0xDC, 0x15, 0xBA, 0x3E, 0x7D, 0x95, 0x3B, 0x2F,
    ]

  /**
  Self-test data for FM17522.
  This is a clone from Fudan Semiconductor.
  Copied from: https://github.com/miguelbalboa/rfid/blob/b2ff919438c2c2924092de8348b19049359dddd0/src/MFRC522.h#L67
  */
  static FM17522 ::= SelfTestData 0x88
    #[
      0x00, 0xD6, 0x78, 0x8C, 0xE2, 0xAA, 0x0C, 0x18,
      0x2A, 0xB8, 0x7A, 0x7F, 0xD3, 0x6A, 0xCF, 0x0B,
      0xB1, 0x37, 0x63, 0x4B, 0x69, 0xAE, 0x91, 0xC7,
      0xC3, 0x97, 0xAE, 0x77, 0xF4, 0x37, 0xD7, 0x9B,
      0x7C, 0xF5, 0x3C, 0x11, 0x8F, 0x15, 0xC3, 0xD7,
      0xC1, 0x5B, 0x00, 0x2A, 0xD0, 0x75, 0xDE, 0x9E,
      0x51, 0x64, 0xAB, 0x3E, 0xE9, 0x15, 0xB5, 0xAB,
      0x56, 0x9A, 0x98, 0x82, 0x26, 0xEA, 0x2A, 0x62,
    ]

  version/int
  bytes/ByteArray

  constructor .version .bytes:

/**
An RFID card.

Also known as "PICC" ("Proximity Inductive Coupling Card").
*/
class Card:
  /** Unknown type of card. */
  static TYPE-UNKNOWN	::= 0

  /** MIFARE Ultralight or Ultralight C. */
  static TYPE-MIFARE-UL ::= 1
  /** MIFARE Classic protocol, 320 bytes. */
  static TYPE-MIFARE-MINI ::= 2
  /** MIFARE Classic protocol, 1KB. */
  static TYPE-MIFARE-1K	::= 3
  /** MIFARE Classic protocol, 4KB. */
  static TYPE-MIFARE-4K ::= 4
  /** MIFARE Plus (2KB or 4KB) or MIFARE DESFire */
  static TYPE-MIFARE-PLUS-DESFIRE ::= 5

  /** The UID of this card. */
  uid/ByteArray
  // The proximity coupling device (aka "transceiver").
  transceiver_/Mfrc522
  sak_/int
  is-closed/bool := false

  constructor transceiver/Mfrc522 uid/ByteArray sak/int:
    if sak & 0x08 != 0: return MifareCard transceiver uid sak
    return Card.private_ transceiver uid sak

  constructor.private_ .transceiver_ .uid .sak_:

  /** Whether this card is ISO-14443-4 compliant. */
  is-iso-14443-4-compliant -> bool:
    return sak_ & 0b00100100 == 0b00100000

  /** Whether this card is ISO-18092 (NFC) compliant. */
  is-iso-18092-compliant -> bool:
    return sak_ & 0b01000100 == 0b01000100

  /**
  The type of this card.

  Note that MIFARE Plus cards might report themselves as generic cards for privace reasons.
  */
  type -> int: return sak-to-type_ sak_ uid

  /**
  Transmits the given $bytes as standard frame to the card.

  Returns the response from the card.
  */
  transceive bytes/ByteArray --check-crc/bool=false -> ByteArray?:
    received-frame := transceiver_.transceive-standard_ bytes --check-crc=check-crc
    if not received-frame: return null
    assert: received-frame.size-in-bits == received-frame.bytes.size * 8
    return received-frame.bytes

  halt_ -> none:
    hlta := #[0x50, 0x00]
    // The transceive will wait for a response, timing out.
    // However, that's not a bad thing to do anyway, as we should give the PICC time to
    // go into HALT state.
    transceiver_.transceive-standard_ hlta

  /**
  Sends a HLTA ('halt' of type A) command to the card.
  */
  close -> none:
    halt_

  static sak-to-type_ sak/int uid/ByteArray -> int:
    // See NXP AN 10833 - MIFARE Type ID Procedure.
    type-bits := sak & 0x7F
    if type-bits == 0x00: return TYPE-MIFARE-UL
    if type-bits == 0x09: return TYPE-MIFARE-MINI
    if type-bits == 0x08: return uid.size == 4 ? TYPE-MIFARE-1K : TYPE-MIFARE-PLUS-DESFIRE
    if type-bits == 0x18: return uid.size == 4 ? TYPE-MIFARE-4K : TYPE-MIFARE-PLUS-DESFIRE
    if type-bits == 0x10: return TYPE-MIFARE-PLUS-DESFIRE
    if type-bits == 0x11: return TYPE-MIFARE-PLUS-DESFIRE
    if type-bits == 0x20: return TYPE-MIFARE-PLUS-DESFIRE
    return TYPE-UNKNOWN

  static type-to-str_ t/int -> string:
    if t == TYPE-UNKNOWN: return "Unknown card"
    if t == TYPE-MIFARE-MINI: return "MIFARE Mini, 320 bytes"
    if t == TYPE-MIFARE-1K: return "MIFARE 1KB"
    if t == TYPE-MIFARE-4K: return "MIFARE 4KB"
    if t == TYPE-MIFARE-PLUS-DESFIRE: return "MIFARE Plus or DESFire"
    if t == TYPE-MIFARE-UL: return "MIFARE Ultralight or Ultralight C"
    unreachable

  stringify -> string:
    uid-str := ""
    uid.do: uid-str += "$(%02x it)"
    return "UID: $uid-str - $(type-to-str_ type)"

// https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf
class MifareCard extends Card:
  /**
  The first block of a Mifare card contains the manufacturer data.
  It is generally read-only (except for "magic" cards), and contains:
  -
  */
  static MANUFACTURER-BLOCK ::= 0

  static MIFARE-READ_ ::= 0x30
  static MIFARE-WRITE_ ::= 0xA0
  static ACK_ ::= #[0x0A]

  /** Default key for Mifare cards. */
  static DEFAULT-KEY := #[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

  constructor transceiver/Mfrc522 uid/ByteArray sak/int:
    super.private_ transceiver uid sak

  authenticate --block/int key/ByteArray=DEFAULT-KEY --is-key-a/bool=true:
    return transceiver_.authenticate_ --uid=uid --block=block --key=key --is-key-a=is-key-a

  is-authenticated -> bool:
    return transceiver_.is-authenticated_

  read --block/int:
    if not 0 <= block <= total-block-count: throw "INVALID_ARGUMENT"
    bytes := #[ MIFARE-READ_, block]
    return transceive bytes --check-crc

  /**
  Writes $bytes to a given block.

  Checks that the data is valid for block 0 (the UUID), that the sector trailer's access
    bits are correct, and that they don't lock out the user from modifying the access
    bits in the future.
  If $force is true, writes the data, without doing any check.
  If $force-lockout is true, verifies that the data is correct, but allows to
    lock out the user from modifying the access bits in the future. The parameter
    $force implies $force-lockout.
  The $force and $force-lockout flags only verify the data in the $bytes array. They
    don't check that the user is allowed to write to the block.
  */
  write --block/int bytes/ByteArray --force/bool=false --force-lockout/bool=false -> none:
    if not 0 <= block <= total-block-count: throw "INVALID_ARGUMENT"
    if bytes.size != 16: throw "MifareCard.write: bytes must be 16 bytes long"
    if block == MANUFACTURER-BLOCK and not force: check-manufacturer-data_ bytes
    if is-trailer-block block and not force: check-trailer-data_ bytes --allow-lockout=(not force-lockout)

    response := transceive #[ MIFARE-WRITE_, block ]
    if response != ACK_: throw (MifareException.from-response response)
    response = transceive bytes
    if response != ACK_: throw (MifareException.from-response response)

  close -> none:
    // Call halt first, before we reset the authentication.
    super
    transceiver_.stop-crypto_

  is-trailer-block block/int:
    if block < (32 * 4):
      return block % 4 == 3
    return block % 16 == 15

  is-first-block-in-sector block/int:
    if block < (32 * 4):
      return block % 4 == 0
    return block % 16 == 0

  sectors-count -> int:
    if type == Card.TYPE-MIFARE-MINI:
      return 5
    else if type == Card.TYPE-MIFARE-1K or type == Card.TYPE-MIFARE-PLUS-DESFIRE:
      return 16
    else if type == Card.TYPE-MIFARE-4K:
      return 40
    throw "Unknown card"

  total-block-count -> int:
    sectors := sectors-count
    if sectors <= 32: return sectors * 4
    return 32 * 4 + (sectors - 32) * 16

  /**
  The size of the given block in blocks.
  */
  sector-size-in-blocks sector/int -> int:
    if sector < 32: return 4
    return 16

  check-keys_ keys/List:
    keys.do:
      if it.size != 6: throw "Keys must be 6 bytes long"

  dump --keys/List=(List sectors-count: DEFAULT-KEY) -> ByteArray:
    check-keys_ keys
    result := ByteArray total-block-count * 16
    sector-counter := 0
    key/ByteArray? := null
    for i := 0; i < total-block-count; i++:
      if is-first-block-in-sector i:
        // Set the key so we can update the trailer block later.
        key = keys[sector-counter]
        authenticated := authenticate --block=i key
        if not authenticated: throw (MifareException.from-code MifareException.AUTHENTICATION-FAILED)
        sector-counter++
      block-bytes := read --block=i
      if is-trailer-block i: block-bytes.replace 0 key
      result.replace (i * 16) block-bytes
    return result

  /**
  Dumps the content of the card to stdout.

  If there is an authentication error automatically reconnects. This might wake up other
    cards that are in the field.
  */
  write-to-stdout --keys/List=(List sectors-count: DEFAULT-KEY) --print-last-first/bool=true:
    check-keys_ keys
    result := ByteArray total-block-count * 16
    sector-counter := 0
    key/ByteArray? := null
    block := 0
    while block < total-block-count:
      if is-first-block-in-sector block:
        if block != 0: print
        print "Sector $sector-counter:"
        // Set the key so we can update the trailer block later.
        key = keys[sector-counter]
        authenticated := authenticate --block=block key
        if not authenticated:
          print "  encrypted"
          reset-communication_
          // Skip over the remaining blocks in this sector.
          block += sector-size-in-blocks sector-counter
          sector-counter++
          continue

      blocks := []
      sector-size := sector-size-in-blocks sector-counter
      for j := 0; j < sector-size; j++:
        block-bytes := read --block=block
        if is-trailer-block block: block-bytes.replace 0 key
        blocks.add block-bytes
        block++

      access-bits := AccessBits.from-trailer blocks.last
      for i := 0; i < blocks.size; i++:
        block-bytes := blocks[i]
        block-str := ""
        block-bytes.do: block-str += "$(%02x it)"
        area/int := ?
        if sector-size == 4:
          area = i
        else
          if i < 5: area = 0
          else if i < 10: area = 1
          else if i < 15: area = 2
          else: area = 3

        legend := access-bits.stringify --area=area

        print "  $block-str ($legend)"

      sector-counter++

  throw-mifare-error_ response/ByteArray:

    if response.size != 1: throw "Invalid response size"
    if response[0] == 0x00: throw "Invalid operation"
    if response[0] == 0x01: throw "Parity or CRC error"

  check-manufacturer-data_ bytes/ByteArray:
    // We assume that the UID must be of the same size as the current UID.
    // Magic cards generally don't allow to switch UID size.
    new-uid-bytes := bytes[..uid.size]
    bcc := 0
    new-uid-bytes.do: bcc ^= it
    if bcc != bytes[uid.size]: throw (MifareException.from-code MifareException.INVALID-UID-BCC)

  check-trailer-data_ byte/ByteArray --allow-lockout/bool:
    access-bits := AccessBits.from-trailer byte
    if allow-lockout: return
    if not access-bits.can-write-access-bits --with-key-a --with-key-b:
      throw (MifareException.from-code MifareException.ACCESS-BITS-LOCKOUT)

  reset-communication_:
    transceiver_.stop-crypto_
    halt_
    transceiver_.wake-up-cards_
    transceiver_.select_ uid

/**
Access bits of a Mifare card.

A trailer block encodes 4 integers, each between 0 and 7.
The first three integers provide the access bits for the data blocks.
The list integer provides the access bits for the trailer block itself.

When a sector has more than 3 data blocks (Mifare 4K), then the access bits are
  applied as follows:
  * b0 (the first byte), applies to blocks 0-4
  * b1 (the second byte), applies to blocks 5-9
  * b2 (the third byte), applies to blocks 10-14

b3 is always the access bits for the trailer block.

The meaning of the access bits for data blocks is as follows:
```
        read write increment decrement/transfer/restore
0b000:   AB   AB      AB       AB    # Transport configuration
0b010:   AB   --      --       --    # read/write block
0b100:   AB    B      --       --    # read/write block
0b110:   AB    B       B       AB    # value block
0b001:   AB   --      --       AB    # value block
0b011:    B    B      --       --    # read/write block
0b101:    B   --      --       --    # read/write block
0b111:   --   --      --       --    # read/write block
```

The meaning of the access bits for the trailer block is as follows.
```
        Key A, Access bits, Key B
0b000: Aw   ,  Ar        , Arw      # Key B is readable.
0b010:      ,  Ar        , Ar       # Key B is readable.
0b100:    Bw,  Ar  Br    ,     Bw
0b110:      ,  Ar  Br    ,
0b001: Aw   ,  Arw       , Arw      # Transport configuration. Key B is readable.
0b011:    Bw,  Ar  Brw   ,     Bw
0b101:      ,  Ar  Brw   ,
0b111:      ,  Ar  Br    ,
```
*/
class AccessBits:
  /**
  Constructs the access bits for a data area.

  Not all combinations of $key-a-read, $key-b-read, $key-a-write, $key-b-write,
    $key-a-increment, $key-b-increment, $key-a-decrement, $key-b-decrement are possible.
  */
  static build-data-area-bits -> int
      --key-a-read/bool --key-b-read/bool
      --key-a-write/bool --key-b-write/bool
      --key-a-increment/bool --key-b-increment/bool
      --key-a-decrement/bool --key-b-decrement/bool:
    if key-a-read and key-b-read and
        key-a-write and key-b-write and
        key-a-increment and key-b-increment and
        key-a-decrement and key-b-decrement:
      return 0b000
    if key-a-read and key-b-read and
        not key-a-write and not key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b010
    if key-a-read and key-b-read and
        not key-a-write and key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b100
    if key-a-read and key-b-read and
        not key-a-write and key-b-write and
        not key-a-increment and key-b-increment and
        key-a-decrement and key-b-decrement:
      return 0b110
    if key-a-read and key-b-read and
        not key-a-write and not key-b-write and
        not key-a-increment and not key-b-increment and
        key-a-decrement and key-b-decrement:
      return 0b001
    if not key-a-read and key-b-read and
        not key-a-write and key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b011
    if not key-a-read and key-b-read and
        not key-a-write and not key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b101
    if not key-a-read and not key-b-read and
        not key-a-write and not key-b-write and
        not key-a-increment and not key-b-increment and
        not key-a-decrement and not key-b-decrement:
      return 0b111
    throw "INVALID_ARGUMENT"

  /**
  Constructs the access bits for a trailer area.

  Not all combinations of
    $read-key-b-with-key-a,
    $write-key-a-with-key-a, $write-key-a-with-key-b,
    $write-key-b-with-key-a, $write-key-b-with-key-b,
    $read-access-bits-with-key-a, $read-access-bits-with-key-b,
    $write-access-bits-with-key-a, $write-access-bits-with-key-b are possible.
  */
  static build-trailer-bits -> int
      --read-key-b-with-key-a/bool
      --write-key-a-with-key-a/bool --write-key-a-with-key-b/bool
      --write-key-b-with-key-a/bool --write-key-b-with-key-b/bool
      --read-access-bits-with-key-a/bool --read-access-bits-with-key-b/bool
      --write-access-bits-with-key-a/bool --write-access-bits-with-key-b/bool:
    if read-key-b-with-key-a and
        write-key-a-with-key-a and not write-key-a-with-key-b and
        write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and not read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b000
    if read-key-b-with-key-a and
        not write-key-a-with-key-a and not write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and not read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b010
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and write-key-a-with-key-b and
        not write-key-b-with-key-a and write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b100
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and not write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b110
    if read-key-b-with-key-a and
        write-key-a-with-key-a and not write-key-a-with-key-b and
        write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and not read-access-bits-with-key-b and
        write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b001
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and write-access-bits-with-key-b:
      return 0b011
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and not write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and write-access-bits-with-key-b:
      return 0b101
    if not read-key-b-with-key-a and
        not write-key-a-with-key-a and not write-key-a-with-key-b and
        not write-key-b-with-key-a and not write-key-b-with-key-b and
        read-access-bits-with-key-a and read-access-bits-with-key-b and
        not write-access-bits-with-key-a and not write-access-bits-with-key-b:
      return 0b111
    throw "INVALID_ARGUMENT"

  b0 /int
  b1 /int
  b2 /int
  b3 /int

  constructor.from-trailer bytes/ByteArray:
    if bytes.size != 16: throw "INVALID_ARGUMENT"
    c1 := bytes[7] >> 4
    c2 := bytes[8] & 0xf
    c3 := bytes[8] >> 4
    c1_ := bytes[6] & 0xf
    c2_ := bytes[6] >> 4
    c3_ := bytes[7] & 0xf

    // cX_ should always be the inverted version of cX.
    if c1_ != 0xf - c1 or c2_ != 0xf - c2 or c3_ != 0xf - c3:
      throw (MifareException.from-code MifareException.INVALID-ACCESS-BITS)
    else:
      b0 = (c1 & 0b0001) << 2 | (c2 & 0b0001) << 1 | (c3 & 0b0001) << 0
      b1 = (c1 & 0b0010) << 1 | (c2 & 0b0010) << 0 | (c3 & 0b0010) >> 1
      b2 = (c1 & 0b0100) << 0 | (c2 & 0b0100) >> 1 | (c3 & 0b0100) >> 2
      b3 = (c1 & 0b1000) >> 1 | (c2 & 0b1000) >> 2 | (c3 & 0b1000) >> 3

  /**
  Builds a instance with the given access bits for each area.
  */
  constructor .b0 .b1 .b2 .b3:
    if not 0 <= b0 <= 7: throw "INVALID_ARGUMENT"
    if not 0 <= b1 <= 7: throw "INVALID_ARGUMENT"
    if not 0 <= b2 <= 7: throw "INVALID_ARGUMENT"
    if not 0 <= b3 <= 7: throw "INVALID_ARGUMENT"

  /**
  Returns whether it is possible to read the blocks covered by the given $area with
    key A (if $with-key-a is true) and/or key B (if $with-key-b is true).

  The $area must be in range 0-2, as this function only covers the access bits for
    data blocks.
  */
  can-read-data --area/int --with-key-a/bool --with-key-b/bool -> bool:
    bits := area-to-bits_ area

    if with-key-a:
      if bits == 0b000 or bits == 0b010 or bits == 0b100 or bits == 0b110 or bits == 0b001: return true
    if with-key-b:
      if bits != 0b111: return true
    return false

  /**
  Returns whether it is possible to write the blocks covered by the given $area with
    key A (if $with-key-a is true) and/or key B (if $with-key-b is true).

  The $area must be in range 0-2, as this function only covers the access bits for
    data blocks.
  */
  can-write-data --area/int --with-key-a/bool --with-key-b/bool -> bool:
    bits := area-to-bits_ area

    if with-key-a and bits == 0b000: return true
    if with-key-b:
      if bits == 0b000 or bits == 0b100 or bits == 0b110 or bits == 0b011: return true
    return false

  /**
  Returns whether is is possible increment the blocks covered by the given $area with
    key A (if $with-key-a is true) and/or key B (if $with-key-b is true).

  The $area must be in range 0-2, as this function only covers the access bits for
    data blocks.
  */
  can-increment-data --area/int --with-key-a/bool --with-key-b/bool -> bool:
    bits := area-to-bits_ area

    if with-key-a and bits == 0b000: return true
    if with-key-b and bits == 0b000 or bits == 0b110: return true
    return false

  /**
  Returns whether is is possible decrement the blocks covered by the given $area with
    key A (if $with-key-a is true) and/or key B (if $with-key-b is true).

  The $area must be in range 0-2, as this function only covers the access bits for
    data blocks.
  */
  can-decrement-data --area/int --with-key-a/bool --with-key-b/bool -> bool:
    bits := area-to-bits_ area

    if not with-key-a and not with-key-b: return false
    return bits == 0b000 or bits == 0b110 or bits == 0b001

  /**
  Returns whether it is possible to read key B of the trailer block with key A.

  Note: there is no `can_read_key_a` as key A is never readable.
  */
  can-read-key-b -> bool:
    return b3 == 0b000 or b3 == 0b010 or b3 == 0b001

  /**
  Whether it is possible to write key A or B of the trailer block with key
    A (if $with-key-a is true) and/or key B (if $with-key-b is true).
  */
  can-write-key --with-key-a/bool --with-key-b/bool -> bool:
    if with-key-a:
      if b3 == 0b000 or b3 == 0b001: return true
    if with-key-b:
    if b3 == 0b100 or b3 == 0b011: return true
    return false

  /**
  Whether it is possible to read the access bits of the trailer block with key B.

  Note: key A can always read the access bits.
  */
  can-read-access-bits --with-key-b/bool -> bool:
    if not with-key-b: return false
    return b3 == 0b100 or b3 == 0b110 or b3 == 0b011 or b3 == 0b101 or b3 == 0b111

  /**
  Whether it is possible to write the access bits of the trailer block with key A
    (if $with-key-a is true) and/or key B (if $with-key-b is true).
  */
  can-write-access-bits --with-key-a/bool --with-key-b/bool -> bool:
    if with-key-a and b3 == 0b001: return true
    if with-key-b:
      if b3 == 0b011 or b3 == 0b101: return true
    return false

  /**
  Writes the access bits into the given $bytes trailer.

  This modifies bytes 6, 7 and 8 of the $bytes.
  */
  write-into-trailer bytes/ByteArray:
    if bytes.size != 16: throw "INVALID_ARGUMENT"

    c1 := (b0 >> 2) & 0b0001 | (b1 >> 1) & 0b0010 | (b2 >> 0) & 0b0100 | (b3 << 1) & 0b1000
    c2 := (b0 >> 1) & 0b0001 | (b1 >> 0) & 0b0010 | (b2 << 1) & 0b0100 | (b3 << 2) & 0b1000
    c3 := (b0 >> 0) & 0b0001 | (b1 << 1) & 0b0010 | (b2 << 2) & 0b0100 | (b3 << 3) & 0b1000
    c1_ := 0xf - c1
    c2_ := 0xf - c2
    c3_ := 0xf - c3
    bytes[6] = (c2_ << 4) | c1_
    bytes[7] = (c1 << 4) | c3_
    bytes[8] = (c3 << 4) | c2

  stringify -> string:
    return """
      $(data-access-bits-to-string b0)
      $(data-access-bits-to-string b1)
      $(data-access-bits-to-string b2)
      $(trailer-access-bits-to-string b3)
      """

  area-to-bits_ area/int -> int:
    if not 0 <= area <= 3: throw "INVALID_ARGUMENT"
    if area == 0: return b0
    else if area == 1: return b1
    else if area == 2: return b2
    return b3

  /**
  Stringifies the access bits for the given $area.

  The $area value must be in range 0-3.
  For Mifare 1K, the $area value is equivalent to the block in the sector.
  For Mifare 4K, the $area value may cover multiple blocks.
  */
  stringify --area/int:
    if not 0 <= area <= 3: throw "INVALID_ARGUMENT"
    if area == 0: return data-access-bits-to-string b0
    if area == 1: return data-access-bits-to-string b1
    if area == 2: return data-access-bits-to-string b2
    return trailer-access-bits-to-string b3

  /**
  Returns a string representation of the access bits of a data block ($b0, $b1, or $b2).
  */
  data-access-bits-to-string area/int -> string:
    if area == 0b000:
      return "000 - read:AB, write:AB, increment:AB, decrement:AB"
    if area == 0b010:
      return "010 - read:AB"
    if area == 0b100:
      return "100 - read:AB, write:B"
    if area == 0b110:
      return "110 - read:AB, write:B, increment:B, decrement:AB"
    if area == 0b001:
      return "001 - read:AB, decrement:AB"
    if area == 0b011:
      return "011 - read:B, write:B"
    if area == 0b101:
      return "101 - read:B"
    if area == 0b111:
      return "111 - no access"
    unreachable

  /**
  Returns a string representation of the access bits of the trailer block ($b3).
  */
  trailer-access-bits-to-string bits/int -> string:
    if bits == 0b000:
      return "000 - Key A: Aw, Bits: Ar, Key B: Arw"
    if bits == 0b010:
      return "010 - Bits: Ar, Key B: Ar"
    if bits == 0b100:
      return "100 - Key A: Bw, Bits: Ar Br,  Key B: Bw"
    if bits == 0b110:
      return "110 - Bits: Ar Br"
    if bits == 0b001:
      return "001 - Key A: Aw, Bits: Arw, Key B: Arw"
    if bits == 0b011:
      return "011 - Key A: Bw, Bits: Ar Brw, Key B: Bw"
    if bits == 0b101:
      return "101 - Bits: Ar Brw"
    if bits == 0b111:
      return "111 - Bits: Ar Br"
    unreachable


class MifareException:
  static INVALID-OPERATION-VALID-BUFFER ::= 0x00
  static PARITY-OR-CRC-ERROR-VALID-BUFFER ::= 0x01
  static INVALID-OPERATION-INVALID-BUFFER ::= 0x04
  static PARITY-OR-CRC-ERROR-INVALID-BUFFER ::= 0x05

  /**
  The card did not return an ACK, but the response did not match any known error code
    or format.
  */
  static INVALID-ERROR-RESPONSE ::= -1
  /**
  When writing the manufacturer block, the BCC (block check character) was found to be
    invalid.
  A BCC is a checksum over the UID bytes, and an invalid BCC can brick magic cards.
  */
  static INVALID-UID-BCC ::= -2
  /**
  Invalid access bits.

  Normaly, the access bits of a trailer block are duplicated in such a way that
    each bit has a corresponding inverted bit. This error is used when that's
    not the case.
  */
  static INVALID-ACCESS-BITS ::= -3

  /**
  The Mifare authentication failed.
  */
  static AUTHENTICATION-FAILED ::= -4

  /**
  Dangerous access bits.

  This code is used when a user tries to write a trailer block with access bits
    that would lock out the owner of the card.
  */
  static ACCESS-BITS-LOCKOUT ::= -5

  /** The received data, if any. */
  response/ByteArray?

  /**
  The code of the error.

  Codes $INVALID-OPERATION-VALID-BUFFER, $PARITY-OR-CRC-ERROR-VALID-BUFFER, $INVALID-OPERATION-INVALID-BUFFER and
    $PARITY-OR-CRC-ERROR-INVALID-BUFFER are responses from the Mifare card. Other codes are defined by this library.
  */
  code/int

  constructor.from-response .response/ByteArray:
    if response.size != 1: code = INVALID-ERROR-RESPONSE
    if response[0] != INVALID-OPERATION-VALID-BUFFER and response[0] != PARITY-OR-CRC-ERROR-VALID-BUFFER and
        response[0] != INVALID-OPERATION-INVALID-BUFFER and response[0] != PARITY-OR-CRC-ERROR-INVALID-BUFFER:
      code = INVALID-ERROR-RESPONSE
    else:
      code = response[0]

  constructor.from-code .code:
    response = null

  stringify -> string:
    if code == INVALID-OPERATION-VALID-BUFFER: return "Invalid operation (valid buffer)"
    if code == PARITY-OR-CRC-ERROR-VALID-BUFFER: return "Parity or CRC error (valid buffer)"
    if code == INVALID-OPERATION-INVALID-BUFFER: return "Invalid operation (invalid buffer)"
    if code == PARITY-OR-CRC-ERROR-INVALID-BUFFER: return "Parity or CRC error (invalid buffer)"
    if code == INVALID-ERROR-RESPONSE: return "Invalid response: $response"
    if code == INVALID-UID-BCC: return "Invalid UID BCC"
    if code == INVALID-ACCESS-BITS: return "Invalid access bits"
    if code == AUTHENTICATION-FAILED: return "Authentication failed"
    return "Unknown error code: $code"
