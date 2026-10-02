#ifndef TEST_H
#define TEST_H
#include "ICommChannel.h"


class CTest: public IProtocolObserver
{
    public:
        CTest();
        virtual ~CTest();
        virtual int OnChannelEvent( uint32_t event,
                                   void* lpEventData );
        virtual int OnChannelData(void* lpData,
                                  uint32_t ulDataSize,
                                  uint32_t reserved =0 );

    protected:
    private:
};

#endif // TEST_H
