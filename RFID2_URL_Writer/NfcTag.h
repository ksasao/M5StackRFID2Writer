#ifndef NfcTag_h
#define NfcTag_h

#include <inttypes.h>
#include <Arduino.h>
#include "NdefMessage.h"

class NfcTag
{
    public:
        enum TagType { TYPE_MIFARE_CLASSIC = 0, TYPE_1, TYPE_2, TYPE_3, TYPE_4, TYPE_UNKNOWN = 99 };
        NfcTag(byte *uid, uint8_t uidLength, TagType tagType);
        NfcTag(byte *uid, uint8_t uidLength, TagType tagType, bool isFormatted);
        NfcTag(byte *uid, uint8_t uidLength, TagType tagType, NdefMessage& ndefMessage);
        NfcTag(byte *uid, uint8_t uidLength, TagType tagType, const byte *ndefData, const uint16_t ndefDataLength);
        ~NfcTag(void);
        NfcTag& operator=(const NfcTag &rhs);
        uint8_t getUidLength();
        void getUid(byte *uid, uint8_t *uidLength);
        String getUidString();
        TagType getTagType();
        bool hasNdefMessage();
        NdefMessage getNdefMessage();
        bool isFormatted();
#ifdef NDEF_USE_SERIAL
        void print();
#endif
    private:
        byte *_uid;
        uint8_t _uidLength;
        TagType _tagType; // Mifare Classic, NFC Forum Type {1,2,3,4}, Unknown
        NdefMessage *_ndefMessage;
        /**
         * if tag is not formatted it is most probably in HALTED state as soon as we realize that
         * because authentication failed => We need to call PICC_WakeupA
         */
        bool _isFormatted; 
        // TODO capacity
};

#endif
