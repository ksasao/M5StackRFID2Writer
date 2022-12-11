// RFID URL Writer for M5Stack RFID 2 Unit (WS1850S/MFRC522 I2C) by ksasao
//
// Writes a Tag single URI record (https://m5stack.com/) to an NFC formatted tag. Note this erases all existing records.
// forked from NDEF Library for Arduino by TheNitek https://github.com/TheNitek/NDEF (BSD License)
//             RFID_RC522 by M5Stack https://github.com/m5stack/M5Stack/tree/master/examples/Unit/RFID_RC522 (MIT license)
#include <M5Atom.h>
#include "MFRC522_I2C.h"
#include "NfcAdapter.h"

MFRC522 mfrc522(0x28); // Create MFRC522 instance
char str[256];

NfcAdapter nfc = NfcAdapter(&mfrc522);

void setup() {
    M5.begin(true,false,true);
    Wire.begin();
    Serial.println("NDEF writer\nPlace a formatted Mifare Classic or Ultralight NFC tag on the reader.");
    mfrc522.PCD_Init(); // Init MFRC522
    nfc.begin();
}

void loop() {
    if (nfc.tagPresent()) {
      // Show Nfc Tag type
      byte piccType = mfrc522.PICC_GetType((&mfrc522.uid)->sak);
      Serial.print("PICC type: ");
      Serial.println(mfrc522.PICC_GetTypeName(piccType));

      // Show Uid
      NfcTag tag = nfc.read();
      Serial.print("UID      : ");
      Serial.println(tag.getUidString());

      const char* url = "https://m5stack.com/";
      snprintf(str, sizeof(str), "%s", url);
      Serial.printf("Writing record to NFC tag: %s\n",str);
      NdefMessage message = NdefMessage();
      message.addUriRecord(url);
      bool success = nfc.write(message);
      if (success) {
        Serial.println(" => Success. Try reading this tag with your phone.");        
        delay(2000);
      } else {
        Serial.println(" => Write failed.");
      }
      Serial.println();
    }
    delay(1000);
}
