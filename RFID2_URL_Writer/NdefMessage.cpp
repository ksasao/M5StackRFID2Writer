#include "NdefMessage.h"

NdefMessage::NdefMessage(void)
{
    _recordCount = 0;
}

NdefMessage::NdefMessage(const byte * data, const uint16_t numBytes)
{
#ifdef NDEF_USE_SERIAL
    Serial.print(F("Decoding "));Serial.print(numBytes);Serial.println(F(" bytes"));
    PrintHexChar(data, numBytes);
#endif

    _recordCount = 0;

    int index = 0;

    while (index < numBytes)
    {

        // decode tnf - first byte is tnf with bit flags
        // see the NFDEF spec for more info
        byte tnf_byte = data[index];
        // bool mb = tnf_byte & 0x80;
        bool me = tnf_byte & 0x40;
        // bool cf = tnf_byte & 0x20;
        bool sr = tnf_byte & 0x10;
        bool il = tnf_byte & 0x8;
        NdefRecord::TNF tnf = static_cast<NdefRecord::TNF>(tnf_byte & 0x7);

        NdefRecord *record = new NdefRecord();
        record->setTnf(tnf);

        index++;
        int typeLength = data[index];

        uint32_t payloadLength = 0;
        if (sr)
        {
            index++;
            payloadLength = data[index];
        }
        else
        {
            payloadLength =
                  (static_cast<uint32_t>(data[index])   << 24)
                | (static_cast<uint32_t>(data[index+1]) << 16)
                | (static_cast<uint32_t>(data[index+2]) << 8)
                |  static_cast<uint32_t>(data[index+3]);
            index += 4;
        }

        int idLength = 0;
        if (il)
        {
            index++;
            idLength = data[index];
        }

        index++;
        record->setType(&data[index], typeLength);
        index += typeLength;

        if (il)
        {
            record->setId(&data[index], idLength);
            index += idLength;
        }

        record->setPayload(&data[index], payloadLength);
        index += payloadLength;

        _records[_recordCount] = record;
        _recordCount++;

        if (me) break; // last message
    }

}

NdefMessage::NdefMessage(const NdefMessage& rhs)
{
    _recordCount = 0;
    for (unsigned int i = 0; i < rhs._recordCount; i++)
    {
        addRecord(*(rhs._records[i]));
    }
}

NdefMessage::~NdefMessage()
{
    for (int i = 0; i < _recordCount; i++)
    {
        delete(_records[i]);
    }
}

NdefMessage& NdefMessage::operator=(const NdefMessage& rhs)
{

    if (this != &rhs)
    {

        // delete existing records
        for (uint8_t i = 0; i < _recordCount; i++)
        {
            delete(_records[i]);
            _records[i] = (NdefRecord*)NULL;
        }

        _recordCount = 0;
        for (unsigned int i = 0; i < _recordCount; i++)
        {
            addRecord(*(rhs._records[i]));
        }
    }
    return *this;
}

uint8_t NdefMessage::getRecordCount()
{
    return _recordCount;
}

unsigned int NdefMessage::getEncodedSize()
{
    unsigned int size = 0;
    for (unsigned int i = 0; i < _recordCount; i++)
    {
        size += _records[i]->getEncodedSize();
    }
    return size;
}

// TODO change this to return uint8_t*
void NdefMessage::encode(uint8_t* data)
{
    // assert sizeof(data) >= getEncodedSize()
    uint8_t* data_ptr = &data[0];

    for (unsigned int i = 0; i < _recordCount; i++)
    {
        _records[i]->encode(data_ptr, i == 0, (i + 1) == _recordCount);
        // TODO can NdefRecord.encode return the record size?
        data_ptr += _records[i]->getEncodedSize();
    }

}

bool NdefMessage::addRecord(NdefRecord &record)
{

    if (_recordCount < MAX_NDEF_RECORDS)
    {
        _records[_recordCount] = new NdefRecord(record);
        _recordCount++;
        return true;
    }
    else
    {
#ifdef NDEF_USE_SERIAL
        Serial.println(F("WARNING: Too many records. Increase MAX_NDEF_RECORDS."));
#endif
        return false;
    }
}

void NdefMessage::addMimeMediaRecord(const char *mimeType, const char *payload)
{
    addMimeMediaRecord(mimeType, (uint8_t *)payload, strlen(payload)+1);
}

void NdefMessage::addMimeMediaRecord(const char *mimeType, byte* payload, const uint16_t payloadLength)
{
    NdefRecord r;
    r.setTnf(NdefRecord::TNF_MIME_MEDIA);
    r.setType((byte *)mimeType, strlen(mimeType)+1);
    r.setPayload(payload, payloadLength);

    addRecord(r);
}

void NdefMessage::addTextRecord(const char *text)
{
    addTextRecord(text, "en");
}

// Limited to language codes <= 5 chars (which is enough for "en" or "en-US")
// Only supports UTF-8 encoding
void NdefMessage::addTextRecord(const char *text, const char *language)
{
    NdefRecord r;

    r.setTnf(NdefRecord::TNF_WELL_KNOWN);

    uint8_t RTD_TEXT[] = { NdefRecord::RTD_TEXT };
    r.setType(RTD_TEXT, sizeof(RTD_TEXT));

    size_t languageLength = strlen(language);
    languageLength = (languageLength > 5 ? 5 : languageLength);

    byte header[6];
    // This is the status byte, we always assume UTF-8 encoding here
    header[0] = languageLength;
    memcpy(header+1, language, languageLength);

    r.setPayload(header, languageLength+1, (byte *)text, strlen(text));

    addRecord(r);
}

void NdefMessage::addUriRecord(const char *uri)
{
    NdefRecord r;
    r.setTnf(NdefRecord::TNF_WELL_KNOWN);

    uint8_t RTD_URI[] = { NdefRecord::RTD_URI };
    r.setType(RTD_URI, sizeof(RTD_URI));

    size_t uriLength = strlen(uri);

    byte header[] = {0x00};

    r.setPayload(header, sizeof(header), (byte *)uri, uriLength);

    addRecord(r);
}

// Type shoulde be something like my.com:xx
void NdefMessage::addExternalRecord(const char *type, const byte *payload, const uint16_t payloadLength)
{
	NdefRecord r;
	r.setTnf(NdefRecord::TNF_EXTERNAL_TYPE);

	r.setType((byte *)type, strlen(type));
    r.setPayload(payload, payloadLength);
	addRecord(r);
}

void NdefMessage::addEmptyRecord()
{
    NdefRecord r;
    r.setTnf(NdefRecord::TNF_EMPTY);
    addRecord(r);
}

NdefRecord NdefMessage::getRecord(uint8_t index)
{
    if (index < _recordCount)
    {
        return *(_records[index]);
    }
    else
    {
        return NdefRecord(); // would rather return NULL
    }
}

NdefRecord NdefMessage::operator[](uint8_t index)
{
    return getRecord(index);
}

#ifdef NDEF_USE_SERIAL
void NdefMessage::print()
{
    Serial.print(F("\nNDEF Message "));Serial.print(_recordCount);Serial.print(F(" record"));
    _recordCount == 1 ? Serial.print(", ") : Serial.print("s, ");
    Serial.print(getEncodedSize());Serial.println(F(" bytes"));

    for (unsigned int i = 0; i < _recordCount; i++)
    {
         _records[i]->print();
    }
}
#endif
