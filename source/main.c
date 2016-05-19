#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include "types.h"
#include "crypto.h"
#include "params.h"

#define SEQUENTIAL_KEY	0

void printBranchInstruction(void* key, u32 opcode)
{
	char* condStr = "";
	char* jumpStr = "B";
	
	if((opcode >> 24) & 1) jumpStr = "BL";

	switch(opcode >> 28)
	{
		case 0b0000 : condStr = "EQ"; break;
		case 0b0001 : condStr = "NE"; break;
		case 0b0010 : condStr = "CS"; break;
		case 0b0011 : condStr = "CC"; break;
		case 0b0100 : condStr = "MI"; break;
		case 0b0101 : condStr = "PL"; break;
		case 0b0110 : condStr = "VS"; break;
		case 0b0111 : condStr = "VC"; break;
		case 0b1000 : condStr = "HI"; break;
		case 0b1001 : condStr = "LS"; break;
		case 0b1010 : condStr = "GE"; break;
		case 0b1011 : condStr = "LT"; break;
		case 0b1100 : condStr = "GT"; break;
		case 0b1101 : condStr = "LE"; break;
		default:
		case 0b1110 : condStr = ""; break;
		case 0b1111 : condStr = "NV"; break;
		
	}
	
	/* Only "clean" branches instruction for now. */
	if((opcode >> 24) == 0xEA || (opcode >> 24) == 0xEB)
	{
		printArray((u8*)key, 16);
		printf(" : %s%s 0x%08X (%08X)\n", jumpStr, condStr, ((opcode & 0x00FFFFFF) << 2) + 0x0801B024, opcode);
	}
}

bool isBranchInstruction(u32 opcode)
{
	u8 instr = (opcode >> 24) & 0xFF;
	if(((instr & 0xF) >> 1) == 0b101) return true;
	return false;
}

int main(int argc, char** argv)
{
	srand(time(NULL));
	printf("Arm9LoaderHax Bruteforce Key Finder - @2016, delebile\n\n");

	paramData param;
	if(parseParams(&param, argc, argv)) printUsage();
	
	printf("Target Address : 0x%08X\n", param.payloadTarget);
	printf("Jump Precision : 0x%X\n\n", param.payloadPrecision);

	if(param.arm9Binary)
	{
		if(strncmp((char*)param.arm9Binary + 0x50, "K9L2", 4) != 0)
		{
			printf("The provided firm is not an N3DS 9.6+ firmware file.\n");
		}
		else
		{
			/* We recycle the some unused arm9bin regions. */
			u8 *curKey = param.arm9Binary + 0x100;
			u8 *tmpBuf = param.arm9Binary + 0x110;

			/* Key initialization ... */
			memset((void*)curKey, 0x00, 0x10);

			/* Below is a reproduction of what the Kernel9Loader does on the console.
			   We bruteforce the routine with random keys in order to find some exploitable
			   situations. */
			printf("Searching for exploitable keys...\n");

			long attempts = 0;
			bool infinite = (param.limit == 0) && (attempts == 0);

			while(infinite || param.limit)
			{				
				/* Setting KeyX. */
				aesSetKey(0x11, (void*)curKey, AES_KEY);
				aesUseKeyslot(0x11);
				memcpy((void*)tmpBuf, (void*)(param.arm9Binary + 0x60), 0x10);
				aesDecrypt((u8*)tmpBuf, 0x10, AES_MODE_ECB);
				aesSetKey(0x16, (void*)tmpBuf, AES_KEY_X);
			
				/* Setting KeyY. */
				aesSetKey(0x16, (void*)(param.arm9Binary + 0x10), AES_KEY_Y);
			
				/* Setting the CTR counter. We advance it to our interested location. */
				memcpy((void*)tmpBuf, (void*)(param.arm9Binary + 0x20), 0x10);
				aesAdvCtr((void*)tmpBuf, 0x1481);
				aesSetIv((void*)tmpBuf);
			
				/* Decrypt the entrypoint region. We skip the rest of the binary in order
				   to improve the speed. */
				u8* outBuf = param.arm9Binary + 0x800;
				u8* inBuf = param.arm9Binary + 0x15010;
				memcpy((void*)outBuf, (void*)inBuf, 0x10);
				aesUseKeyslot(0x16);
				aesDecrypt(outBuf, 0x10, AES_MODE_CTR);
				
				/* Analyze the result. */
				u32 opcode = *(u32*)(outBuf + 0x0C);
				u32 addr = ((opcode & 0x00FFFFFF) << 2) + 0x0801B024;
				
				attempts++;
				if(isBranchInstruction(opcode))
				{
					if((addr >= param.payloadTarget && addr <= param.payloadTarget + param.payloadPrecision))
					{
						printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b[#%05ld] ", attempts);
						printBranchInstruction((void*)curKey, opcode);
					}
				}else if((attempts % 10000) == 0)
					printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b[#%05ld]", attempts);
				
				/* Try a new key. */
				if(param.keystore)
				{
					if(feof(param.keystore)) break;
					fread(curKey, 1, 0x10, param.keystore);
				}
				else if(!SEQUENTIAL_KEY)
				{
					for(int i = 0; i < 0x10; i++)
					{
						curKey[i] = (u8)(rand() % 0x100);
					}
					param.limit--;
				}
				else
				{
					aesAdvCtr((void*)curKey, 1);
					param.limit--;
				}
			}
			if(param.keystore) fclose(param.keystore);
			free(param.arm9Binary);
			return 0;
		}
	}
	if(param.keystore) fclose(param.keystore);
	if(param.arm9Binary) free(param.arm9Binary);
	return 1;
}
