#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include "types.h"
#include "crypto.h"

/* You can specify where you will put your payload, the bruteforcer will try his best.
   Depending on how precise you want it to be, it will take more time. */
u32 payloadDesiredPlace = 0x08006000 + 0x89A00;
u32 payloadMaxDislocation = 0x1000;
u8* arm9Binary = NULL;
u32 arm9BinarySize = 0;

void printBranchInstruction(void* key, u32 opcode)
{
	char* condStr = "";
	char* jumpStr = "";
	
	if(((opcode >> 24) & 0xFF) == 0xEA) jumpStr = "B";
	if(((opcode >> 24) & 0xFF) == 0xEB) jumpStr = "BL";

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
	printArray((u8*)key, 16);
	printf(" : %s%s 0x%08X (%08X)\n", jumpStr, condStr, ((opcode & 0x00FFFFFF) << 2) + 0x0801B024, opcode);
}

int openArm9Bin(char* firmPath)
{
	FILE* file = fopen(firmPath, "rb");
	if(file)
	{
		u32 sectionType = 1;
		u32 off = 0;
		u32 size = 0;
		for(int i = 0; i < 4; i++)
		{
			/* Navigate through FIRM header. */
			fseek(file, 0x40 + i*0x30 + 0xC, 0);
			fread(&sectionType, 1, 4, file);

			/* ARM9 section type is 0, ARM11 is 1. */
			if(!sectionType)
			{
				fseek(file, 0x40 + i*0x30, 0);
				fread(&off, 1, 4, file);
				fread(&size, 1, 4, file);	// Skip the Address, is not interesting here.
				fread(&size, 1, 4, file);
				break;
			}
		}
		if(off && size)
		{
			arm9Binary = (u8*) malloc (size);
			arm9BinarySize = size;
			fseek(file, off, 0);
			fread(arm9Binary, 1, arm9BinarySize, file);
			fclose(file);
			return 0;
		}
		fclose(file);
	}
	return 1;
}

bool isBranchInstruction(u32 opcode)
{
	u8 instr = (opcode >> 24) & 0xFF;
	if(instr == 0xEA || instr == 0xEB) return true;
	return false;
}

int main(int argc, char** argv)
{
	srand(time(NULL));
	printf("Arm9LoaderHax Bruteforce Key Finder - @2016, delebile\n\n");

	if(argc != 2)
	{
		printf("Usage : %s <firm_file>\n", APPNAME);
		return 1;
	}

	printf("Loading ARM9 binary... ");
	int res = openArm9Bin(argv[1]);
	printf("%s!\n", res ? "FAIL" : "OK");


    if(!res)
    {
    	if(strncmp((char*)arm9Binary + 0x50, "K9L2", 4) != 0)
    	{
    		printf("The provided firm is not an N3DS 9.6+ firmware file.\n");
    	}
    	else
    	{
    		/* We recycle the some arm9bin regions. */
			u8 *curKey = arm9Binary + 0x100;
			u8 *tmpBuf = arm9Binary + 0x110;
			/* Key randomization... */
    		memset((void*)curKey, 0x00, 0x10);
    		for(int i = 0; i < 0x10; i++)
			{
				curKey[i] = (u8)(rand() % 0x100);
			}

    		/* Below is a reproduction of what the Kernel9Loader does on the console.
    		   We bruteforce the routine with random keys in order to find some exploitable
    		   situations. */
    		printf("Searching for exploitable keys...\n");
    		long attempts = 0;

    		while(1)
			{
				/* Setting KeyX. */
				aesSetKey(0x11, (void*)curKey, AES_KEY);
				aesUseKeyslot(0x11);
				memcpy((void*)tmpBuf, (void*)(arm9Binary + 0x60), 0x10);
				aesDecrypt((u8*)tmpBuf, 0x10, AES_MODE_ECB);
				aesSetKey(0x16, (void*)tmpBuf, AES_KEY_X);
	
				/* Setting KeyY. */
				aesSetKey(0x16, (void*)(arm9Binary + 0x10), AES_KEY_Y);
	
				/* Setting the CTR counter. We advance it to our interested location. */
				memcpy((void*)tmpBuf, (void*)(arm9Binary + 0x20), 0x10);
				aesAdvCtr((void*)tmpBuf, 0x1481);
				aesSetIv((void*)tmpBuf);
	
				/* Decrypt the entrypoint region. We skip the rest of the binary in order
				   to improve the speed. */
				u8* outBuf = arm9Binary + 0x800;
				u8* inBuf = arm9Binary + 0x15010;
				memcpy((void*)outBuf, (void*)inBuf, 0x10);
				aesUseKeyslot(0x16);
				aesDecrypt(outBuf, 0x10, AES_MODE_CTR);
				
				/* Analyze the result. */
				u32 opcode = *(u32*)(outBuf + 0x0C);
				u32 addr = ((opcode & 0x00FFFFFF) << 2) + 0x0801B024;
				
				attempts++;
				if(isBranchInstruction(opcode))
				{
					if((addr >= payloadDesiredPlace && addr <= payloadDesiredPlace + payloadMaxDislocation))
					{
						printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b[#%05ld] ", attempts);
						printBranchInstruction((void*)curKey, opcode);
					}
				}else
					printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b[#%05ld]", attempts);

				/* Try a new key. */
				aesAdvCtr((void*)curKey, 1);
			}
			free(arm9Binary);
			return 0;
		}
    }
    if(arm9Binary) free(arm9Binary);
	return 1;
}
