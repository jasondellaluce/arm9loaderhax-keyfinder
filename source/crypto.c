#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdbool.h>
#include "crypto.h"
#include "polarssl/aes.h"

typedef struct {
	u8 keyX[AES_KEY_SIZE];
	u8 keyY[AES_KEY_SIZE];
	u8 key[AES_KEY_SIZE];
} aesKeyslot;

aesKeyslot keyslots[0x40] = {
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	},
	{
		DUMMYKEY, DUMMYKEY, DUMMYKEY
	}
};

u8 ctr[AES_KEY_SIZE] = {0};
u8 curKeyslot = 0;

/* https://github.com/profi200/Project_CTR/blob/master/ctrtool/utils.c#L39 */
u64 getbe64(const u8* p)
{
	u64 n = 0;

	n |= (u64)p[0]<<56;
	n |= (u64)p[1]<<48;
	n |= (u64)p[2]<<40;
	n |= (u64)p[3]<<32;
	n |= (u64)p[4]<<24;
	n |= (u64)p[5]<<16;
	n |= (u64)p[6]<<8;
	n |= (u64)p[7]<<0;
	return n;
}

/* https://github.com/profi200/Project_CTR/blob/master/ctrtool/utils.c#L114 */
void putbe64(u8* p, u64 n)
{
	p[7] = (u8) n;
	p[6] = (u8) (n >> 8);
	p[5] = (u8) (n >> 16);
	p[4] = (u8) (n >> 24);
	p[3] = (u8) (n >> 32);
	p[2] = (u8) (n >> 40);
	p[1] = (u8) (n >> 48);
	p[0] = (u8) (n >> 56);
}

u8* rolArray(u8* arr, u32 arrLen, int nShift)
{
	u64 arrLow = getbe64(arr);
	u64 arrHigh = getbe64(arr + 8);
	while(nShift--)
	{
		u8 carryLow = (arrLow & 0x8000000000000000LL) ? 1 : 0;
		u8 carryHigh = (arrHigh & 0x8000000000000000LL) ? 1 : 0;
		arrLow = (arrLow << 1) | carryHigh;
		arrHigh = (arrHigh << 1) | carryLow;
	}
	putbe64(arr, arrLow);
	putbe64(arr + 8, arrHigh);
	return arr;
}

u8* rorArray(u8* arr, u32 arrLen, int nShift)
{
	return rolArray(arr, arrLen, arrLen*8-nShift);
}

void sumArray(u8* arr1, u8* arr2, int len)
{
	u64 arr1Low = getbe64(arr1);
	u64 arr1High = getbe64(arr1 + 8);
	u64 arr2Low = getbe64(arr2);
	u64 arr2High = getbe64(arr2 + 8);

	u8 carryHigh = ((arr1High & 0x8000000000000000LL) && (arr2High & 0x8000000000000000LL)) ? 1 : 0;
	arr1Low = (arr1Low + arr2Low) | carryHigh;
	arr1High = arr1High + arr2High;

	putbe64(arr1, arr1Low);
	putbe64(arr1 + 8, arr1High);
}

void printArray(u8* arr, u32 len)
{
	for(int i = 0; i < len; i++)
		printf("%02X", arr[i]);
}

void printArrayBin(u8* arr, u32 len)
{
	for(int i = 0; i < len; i++)
	{
		for(int j = 7; j >= 0; j--)
		{
			printf("%d", (int)((arr[i] & (1 << j)) != 0));
		}
	}
}

void aesUseKeyScrambler(u8 keyslot)
{
	if(keyslot > 0x3F) return;
	u8 costant[] = {0x1F, 0xF9, 0xE9, 0xAA, 0xC5, 0xFE, 0x04, 0x08, 0x02, 0x45, 0x91, 0xDC, 0x5D, 0x52, 0x76, 0x8A};

	u8* tmpKey = (u8*) malloc (AES_KEY_SIZE);
	memcpy((void*)tmpKey, (void*)keyslots[keyslot].keyX, AES_KEY_SIZE);
	rolArray(tmpKey, 16, 2);
	for(int i = 0; i < AES_KEY_SIZE; i++)
	{
		tmpKey[i] ^= keyslots[keyslot].keyY[i];
	}
	sumArray(tmpKey, costant, AES_KEY_SIZE);
	rolArray(tmpKey, 16, 87);
	memcpy((void*)keyslots[keyslot].key, (void*)tmpKey, AES_KEY_SIZE);
	free(tmpKey);
}

void aesUseKeyslot(u8 keyslot)
{
	if(keyslot > 0x3F) return;
	curKeyslot = keyslot;
}

void aesSetKey(u8 keyslot, void* key, u32 keyType)
{
	if(keyslot > 0x3F) return;
	switch(keyType)
	{
		default:
		case AES_KEY:
			memcpy((void*)keyslots[keyslot].key, (void*)key, AES_KEY_SIZE);
			break;
		case AES_KEY_X:
			memcpy((void*)keyslots[keyslot].keyX, (void*)key, AES_KEY_SIZE);
			break;
		case AES_KEY_Y:
			memcpy((void*)keyslots[keyslot].keyY, (void*)key, AES_KEY_SIZE);
			aesUseKeyScrambler(keyslot);
			break;
	}
}

void aesSetIv(void* iv)
{
	memcpy((void*)ctr, (void*)iv, AES_KEY_SIZE);
}

void aesAdvCtr(void* ctr, u32 val)
{
	u8 add[AES_KEY_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	while(val--)
	{
		sumArray((u8*)ctr, (u8*)add, AES_KEY_SIZE);
	}
}

void aesDecrypt(u8* buffer, u32 size, u32 mode)
{
	u8 *tmp = (u8*) malloc (16);
	u32 tmpu32 = 0;
	u8 tmpBuf[16];
	aes_context ctx;
	if(mode == AES_MODE_CTR)
		aes_setkey_enc(&ctx, keyslots[curKeyslot].key, 128);
	else
		aes_setkey_dec(&ctx, keyslots[curKeyslot].key, 128);
	for(int i = 0; i < size; i += 16)
	{
		memset((void*)tmp, 0x00, 16);
		memset((void*)tmpBuf, 0x00, 16);
		tmpu32 = 0;
		switch(mode)
		{
			case AES_MODE_ECB:
				aes_crypt_ecb(&ctx, AES_DECRYPT, buffer + i, tmp);
				break;
			case AES_MODE_CTR:
				aes_crypt_ctr(&ctx, 16, &tmpu32, ctr, tmpBuf, buffer + i, tmp);
				break;
		}
		memcpy((void*)(buffer + i), (void*)tmp, 16);
	}
	free(tmp);
}

void aesEncrypt(u8* buffer, u32 size, u32 mode)
{
	u8 *tmp = (u8*) malloc (16);
	u32 tmpu32 = 0;
	u8 tmpBuf[16];
	aes_context ctx;
	aes_setkey_enc(&ctx, keyslots[curKeyslot].key, 128);
	for(int i = 0; i < size; i += 16)
	{
		memset((void*)tmp, 0x00, 16);
		memset((void*)tmpBuf, 0x00, 16);
		tmpu32 = 0;
		switch(mode)
		{
			case AES_MODE_ECB:
				aes_crypt_ecb(&ctx, AES_ENCRYPT, buffer + i, tmp);
				break;
			case AES_MODE_CTR:
				aes_crypt_ctr(&ctx, 16, &tmpu32, ctr, tmpBuf, buffer + i, tmp);
				break;
		}	
		memcpy((void*)(buffer + i), (void*)tmp, 16);
	}
	free(tmp);
}