#ifndef NdefMessage_h
#define NdefMessage_h

#include "Ndef.h"
#include "NdefRecord.h"

#define MAX_NDEF_RECORDS 4

class NdefMessage
{
    public:
        NdefMessage(void);
        NdefMessage(const byte *data, const uint16_t numBytes);
        NdefMessage(const NdefMessage& rhs);
        ~NdefMessage();
        NdefMessage& operator=(const NdefMessage& rhs);

        unsigned int getEncodedSize(); // need so we can pass array to encode
        void encode(byte *data);

        boolean addRecord(NdefRecord& record);
        void addMimeMediaRecord(const char *mimeType, const char *payload);
        void addMimeMediaRecord(const char *mimeType, byte *payload, const uint16_t payloadLength);
        void addTextRecord(const char *text);
        void addTextRecord(const char *text, const char *encoding);
        void addUriRecord(const char *uri);
        void addExternalRecord(const char *type, const byte *payload, const uint16_t payloadLength);
        void addEmptyRecord();

        uint8_t getRecordCount();
        NdefRecord getRecord(uint8_t index);
        NdefRecord operator[](uint8_t index);

#ifdef NDEF_USE_SERIAL
        void print();
#endif
    private:
        NdefRecord *_records[MAX_NDEF_RECORDS];
        uint8_t _recordCount;
};

#endif
