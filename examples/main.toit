// Copyright (C) 2022 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

import mfrc522
import mifare-classic
import nfc.card-type show CardType
import spi
import gpio

SPI-MOSI ::= 23
SPI-MISO ::= 19
SPI-CLK ::= 18
SPI-SS ::= 5

/*
rkf rejsekort denmark
sector 0-7:   a: fc00018778f7  b: 00000ffe2488
sector 8-12:  a: 0297927c0f77  b: ee0042f88840
sector 13-38: a: 722bfcc5375f  b: f1d83f964314
sector 39:    a: fc00018778f7  b: 00000ffe2488

Idraetscentre:
sector 4-14: a: 3E65E4FB65B3
*/

REJSEKORT-UID ::= #[ 0x2b, 0x53, 0x23, 0x83 ]
REJESKORT-KEYS ::= (::
  key1 := #[ 0xfc, 0x00, 0x01, 0x87,0x78,0xf7]
  key2 := #[ 0x02, 0x97, 0x92, 0x7c,0x0f,0x77]
  key3 := #[ 0x72, 0x2b, 0xfc, 0xc5,0x37,0x5f]
  key4 := #[ 0xfc, 0x00, 0x01, 0x87,0x78,0xf7]

  keys := []
  8.repeat: keys.add key1
  5.repeat: keys.add key2
  26.repeat: keys.add key3
  keys.add key4
  keys
).call

IDRAET-UID ::= #[ 0x04, 0x17, 0x99, 0xf2, 0xda, 0x61, 0x80 ]
IDRAET-KEYS ::= (::
  key1 := #[ 0x3e, 0x65, 0xe4, 0xfb,0x65,0xb3]
  keys := []
  4.repeat: keys.add mifare-classic.ClassicCard.DEFAULT-KEY
  11.repeat: keys.add key1
  keys.add mifare-classic.ClassicCard.DEFAULT-KEY
  keys
).call

main:
  bus := spi.Bus
      --clock = gpio.Pin SPI-CLK
      --mosi = gpio.Pin SPI-MOSI
      --miso = gpio.Pin SPI-MISO

  device := bus.device --cs=(gpio.Pin SPI-SS) --frequency=1_000_000

  reader := mfrc522.Mfrc522 device

  reader.self-test

  reader.on

  iteration := 0
  while true:
    iteration++

    catch --trace:
      found-piccs := []
      reader.do --new:
        print "--------------- $iteration $it"
        found-piccs.add it

      is-mifare-classic := : | type/int |
        type == CardType.MIFARE-MINI or type == CardType.MIFARE-1K or
            type == CardType.MIFARE-4K or type == CardType.MIFARE-PLUS-DESFIRE

      found-piccs.do:
        reader.with-picc it.uid:
          if is-mifare-classic.call it.type:
            mifare := mifare-classic.ClassicCard it

            // dump := mifare.dump
            // List.chunk_up 0 dump.size 16: | from to |
            //   print dump[from..to]

            keys := null
            if mifare.uid == REJSEKORT-UID:
              keys = REJESKORT-KEYS
            else if mifare.uid == IDRAET-UID:
              keys = IDRAET-KEYS

            print "uid: $mifare.uid"
            mifare.write-to-stdout --keys=keys
            print "done"

            // mifare.authenticate --block=3 --is_key_a (keys and keys[0])
            // trailer := mifare.read --block=3
            // access_bits := mfrc522.AccessBits.from_trailer trailer
            // print "Access bits:\n$access_bits"
            // print "trailer: $trailer"
            // access_bits.write_into_trailer trailer
            // print "after:   $trailer"
            // access_bits2 := mfrc522.AccessBits.from_trailer trailer
            // print "Access bits2:\n$access_bits2"

            // key1 := #[ 0x3e, 0x65, 0xe4, 0xfb,0x65,0xb3]
            // keys := []
            // 5.repeat: keys.add mfrc522.MifareCard.DEFAULT_KEY
            // 11.repeat: keys.add key1
            // keys.add mfrc522.MifareCard.DEFAULT_KEY
            // mifare.write_to_stdout --keys=keys

            // for i := 63; i >= 0; i--:
            //   is_first_block_in_sector := (i + 1) % 4 == 0
            //   if is_first_block_in_sector:
            //     mifare.authenticate --block=i
            //   if not mifare.is_authenticated:
            //     print "Block $i encrypted"
            //     mifare.transceiver_.stop_crypto_
            //     continue
            //   block_data := mifare.read --block=i
            //   is_trailer_block := (i + 1) % 4 == 0
            //   trailer_suffix := ""
            //   access_bits := null
            //   if is_trailer_block:
            //     exception := catch: access_bits = mifare.access_bits_from_trailer block_data
            //     if exception:
            //       trailer_suffix = " (invalid access_bits)"
            //     else:
            //       trailer_suffix = " (access bits: $(%x access_bits[0]) $(%x access_bits[1]) $(%x access_bits[2]) $(%x access_bits[3]))"

            //   print "$block_data$trailer_suffix"

            // if mifare.uid == #[0x13, 0x59, 0x70, 0x15]:
            //   print "writing to block 2 of sector 1"
            //   mifare.authenticate --block=5
            //   print "old: $(mifare.read --block=5)"
            //   mifare.write --block=5 #[ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f ]

    reader.antenna-off
    sleep --ms=2_000
    reader.antenna-on
