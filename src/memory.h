/*

 The MIT License (MIT)

 Copyright (c) 2015 Douglas J. Bakkum

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/



#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <stdint.h>

#define MEM_PAGE_LEN                32

#define MEM_AESKEY_STAND_ADDR       0x0600// Zone 6
#define MEM_AESKEY_VERIFY_ADDR      0x0700// Zone 7
#define MEM_AESKEY_CRYPT_ADDR       0x0800// Zone 8


typedef enum PASSWORD_ID {
    PASSWORD_STAND,
    PASSWORD_VERIFY,
    PASSWORD_MEMORY,
    PASSWORD_CRYPT,
    PASSWORD_2FA,    /* only kept in RAM */
    PASSWORD_NONE    /* keep last */
} PASSWORD_ID;


int memory_write_aeskey(const char *password, int len, PASSWORD_ID id);
uint8_t *memory_read_aeskey(PASSWORD_ID id);


#endif  // _MEMORY_H_
