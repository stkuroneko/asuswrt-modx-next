#include "Test.h"
#include <stddef.h>
#include <stdio.h>

CTest::CTest()
{
    //ctor
}

CTest::~CTest()
{
    //dtor
}

int CTest::OnChannelEvent( uint32_t event,
                          void* lpEventData )
{
    return 0;
}
int CTest::OnChannelData(void* lpData,
                        uint32_t ulDataSize,
                        uint32_t reserved  )
{
    if(ulDataSize!= 0 && lpData != NULL)
    {
        printf((char*)lpData);
    }

    return 0;
}
