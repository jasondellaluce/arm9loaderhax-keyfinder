#pragma once

#include "types.h"

#define AES_KEY_SIZE	16
#define AES_MODE_ECB	0
#define AES_MODE_CBC	1
#define AES_MODE_CTR	2
#define AES_KEY_Y		0
#define AES_KEY_X		1
#define AES_KEY			2
#define DUMMYKEY		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// Array printing functions, always useful
void printArray(u8* arr, u32 len);
void printArrayBin(u8* arr, u32 len);

// 3DS AES Engine simulator
void aesUseKeyslot(u8 keyslot);
void aesSetKey(u8 keyslot, void* key, u32 keyType);
void aesSetIv(void* iv);
void aesAdvCtr(void* ctr, u32 val);
void aesDecrypt(u8* buffer, u32 size, u32 mode);
void aesEncrypt(u8* buffer, u32 size, u32 mode);

