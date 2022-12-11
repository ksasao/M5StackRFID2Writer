#include "NfcAdapter.h"

NfcAdapter::NfcAdapter(MFRC522 *interface)
{
    shield = interface;
}

NfcAdapter::~NfcAdapter(void)
{
}

void NfcAdapter::begin(bool verbose)
{
#ifdef NDEF_USE_SERIAL
    if (verbose)
    {
        shield->PCD_DumpVersionToSerial();
    }
#endif
}

bool NfcAdapter::tagPresent()
{
    // If tag has already been authenticated nothing else will work until we stop crypto (shouldn't hurt)
    shield->PCD_StopCrypto1();

    if(!(shield->PICC_IsNewCardPresent() && shield->PICC_ReadCardSerial()))
    {
        return false;
    }

    MFRC522::PICC_Type piccType = (MFRC522::PICC_Type)shield->PICC_GetType(shield->uid.sak);
    return ((piccType == MFRC522::PICC_TYPE_MIFARE_1K) || (piccType == MFRC522::PICC_TYPE_MIFARE_UL));
}

bool NfcAdapter::erase()
{
    NdefMessage message = NdefMessage();
    message.addEmptyRecord();
    return write(message);
}

bool NfcAdapter::format()
{
#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if(shield->PICC_GetType(shield->uid.sak) == MFRC522::PICC_TYPE_MIFARE_1K)
    {
        MifareClassic mifareClassic = MifareClassic(shield);
        return mifareClassic.formatNDEF();
    }
    else
#endif
    if(shield->PICC_GetType(shield->uid.sak) == MFRC522::PICC_TYPE_MIFARE_UL)
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("No need for formating a UL"));
#endif
        return true;
    }
    else
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("Unsupported Tag."));
#endif
        return false;
    }
}

bool NfcAdapter::clean()
{
    NfcTag::TagType type = guessTagType();

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (type == NfcTag::TYPE_MIFARE_CLASSIC)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Cleaning Mifare Classic"));
        #endif
        MifareClassic mifareClassic = MifareClassic(shield);
        return mifareClassic.formatMifare();
    }
    else
#endif
    if (type == NfcTag::TYPE_2)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Cleaning Mifare Ultralight"));
        #endif
        MifareUltralight ultralight = MifareUltralight(shield);
        return ultralight.clean();
    }
    else
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("No driver for card type "));Serial.println(type);
#endif
        return false;
    }

}

NfcTag NfcAdapter::read()
{
    uint8_t type = guessTagType();

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (type == NfcTag::TYPE_MIFARE_CLASSIC)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Reading Mifare Classic"));
        #endif
        MifareClassic mifareClassic = MifareClassic(shield);
        return mifareClassic.read();
    }
    else
#endif
    if (type == NfcTag::TYPE_2)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Reading Mifare Ultralight"));
        #endif
        MifareUltralight ultralight = MifareUltralight(shield);
        return ultralight.read();
    }
    else if (type == NfcTag::TYPE_UNKNOWN)
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("Can not determine tag type"));
#endif
        return NfcTag(shield->uid.uidByte, shield->uid.size, NfcTag::TYPE_UNKNOWN);
    }
    else
    {
        // Serial.print(F("No driver for card type "));Serial.println(type);
        // TODO should set type here
        return NfcTag(shield->uid.uidByte, shield->uid.size, NfcTag::TYPE_UNKNOWN);
    }

}

bool NfcAdapter::write(NdefMessage& ndefMessage)
{
    uint8_t type = guessTagType();

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (type == NfcTag::TYPE_MIFARE_CLASSIC)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Writing Mifare Classic"));
        #endif
        MifareClassic mifareClassic = MifareClassic(shield);
        return mifareClassic.write(ndefMessage);
    }
    else
#endif
    if (type == NfcTag::TYPE_2)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Writing Mifare Ultralight"));
        #endif
        MifareUltralight mifareUltralight = MifareUltralight(shield);
        return mifareUltralight.write(ndefMessage);
    }
    else if (type == NfcTag::TYPE_UNKNOWN)
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("Can not determine tag type"));
#endif
        return false;
    }
    else
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("No driver for card type "));Serial.println(type);
#endif
        return false;
    }
}

// Current tag will not be "visible" until removed from the RFID field
void NfcAdapter::haltTag() {
    shield->PICC_HaltA();
    shield->PCD_StopCrypto1();
}

NfcTag::TagType NfcAdapter::guessTagType()
{

    MFRC522::PICC_Type piccType = (MFRC522::PICC_Type)shield->PICC_GetType(shield->uid.sak);

    if (piccType == MFRC522::PICC_TYPE_MIFARE_1K)
    {
        return NfcTag::TYPE_MIFARE_CLASSIC;
    } 
    else if (piccType == MFRC522::PICC_TYPE_MIFARE_UL)
    {
        return NfcTag::TYPE_2;
    }
    else
    {
        return NfcTag::TYPE_UNKNOWN;
    }
}
