// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

/**
A driver for the MFRC522 RFID reader.
*/

import serial
import nfc.card-type show CardType
import nfc.crc show crc-a check-crc-a
import nfc.frame show Frame
import nfc.nfc-exception show NfcException
import nfc.reader show Reader ReaderCapabilities Target RawFrameTarget

class Mfrc522 implements Reader:
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
  static COMMAND-SOFT-RESET_ ::= 0x0F          // Resets the MFRC522.

  registers_ /serial.Registers

  current-framing_ /int? := null
  current-parity_ /int? := null

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

  off -> none:
    antenna-off

  capabilities -> ReaderCapabilities:
    return ReaderCapabilities
        --supports-raw-frames
        --no-firmware-does-anticollision

  /**
  Polls once for a target in the field.

  See $Reader.poll.
  */
  poll --new/bool=false -> Target?:
    if not wake-up-cards_ --only-new=new: return null
    catch --unwind=(: not (it is NfcException and it.code == NfcException.NO-RESPONSE)):
      return select_
    return null

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
  */
  transceive-standard_ bytes/ByteArray --check-crc/bool=false --add-crc/bool=true -> Frame?:
    if add-crc:
      crc := crc-a bytes
      bytes += #[crc & 0xFF, (crc >> 8) & 0xFF]

    frame := Frame bytes
    result-frame := transceive_ frame

    if not result-frame: return null

    if not check-crc: return result-frame

    assert: not result-frame.collision-position
    assert: result-frame.bytes.size * 8 == result-frame.size-in-bits
    check-crc-a result-frame.bytes
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
    registers_.write-u8 COMMAND-REGISTER_ COMMAND-TRANSCEIVE_

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
class Card implements Target RawFrameTarget:
  /** The UID of this card. */
  uid/ByteArray
  // The proximity coupling device (aka "transceiver").
  transceiver_/Mfrc522
  sak_/int
  is-closed/bool := false

  constructor transceiver/Mfrc522 uid/ByteArray sak/int:
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
  type -> int: return CardType.from-sak sak_ uid

  /**
  Transmits the given $bytes as standard frame to the card.

  Returns the response from the card.
  */
  transceive bytes/ByteArray --check-crc/bool=false -> ByteArray?:
    received-frame := transceiver_.transceive-standard_ bytes --check-crc=check-crc
    if not received-frame: return null
    assert: received-frame.size-in-bits == received-frame.bytes.size * 8
    return received-frame.bytes

  /** See $RawFrameTarget.transceive-raw. */
  transceive-raw frame/Frame -> Frame?:
    return transceiver_.transceive_ frame

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

  stringify -> string:
    uid-str := ""
    uid.do: uid-str += "$(%02x it)"
    return "UID: $uid-str - $(CardType.to-string type)"

