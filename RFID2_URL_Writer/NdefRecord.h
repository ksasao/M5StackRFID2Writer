#ifndef NdefRecord_h
#define NdefRecord_h

#include "Due.h"
#include <Arduino.h>
#include "Ndef.h"


class NdefRecord
{
    public:
        enum TNF {TNF_EMPTY, TNF_WELL_KNOWN, TNF_MIME_MEDIA, TNF_ABSOLUTE_URI, TNF_EXTERNAL_TYPE, TNF_UNKNOWN, TNF_UNCHANGED, TNF_RESERVED};
        enum RTD {RTD_TEXT = 0x54, RTD_URI = 0x55};
        NdefRecord();
        NdefRecord(const NdefRecord& rhs);
        ~NdefRecord();
        NdefRecord& operator=(const NdefRecord& rhs);

        unsigned int getEncodedSize();
        void encode(byte *data, bool firstRecord, bool lastRecord);

        unsigned int getTypeLength();
        unsigned int getPayloadLength();
        unsigned int getIdLength();

        NdefRecord::TNF getTnf();

        const byte* getType();
        const byte* getPayload();
        const byte* getId();

        void setTnf(NdefRecord::TNF tnf);
        void setType(const byte *type, const unsigned int numBytes);
        void setPayload(const byte *payload, const int numBytes);
        void setPayload(const byte *header, const int headerLength, const byte *payload, const int payloadLength);
        void setId(const byte *id, const unsigned int numBytes);

#ifdef NDEF_USE_SERIAL
        void print();
#endif
    private:
        byte _getTnfByte(bool firstRecord, bool lastRecord);
        TNF _tnf; // 3 bit
        unsigned int _typeLength;
        unsigned int _payloadLength;
        unsigned int _idLength;
        byte *_type;
        byte *_payload;
        byte *_id;
};

#endif
