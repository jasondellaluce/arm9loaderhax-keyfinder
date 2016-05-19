#include "params.h"
#include <string.h>
#include <stdlib.h>

bool isHexString(char* str)
{
	while(*str++)
	{ 
		if((*str >= 'A' && *str <= 'F') || (*str >= 'a' && *str <= 'f'))
			return true;
	}
	return false;
}

int parseParams(paramData* data, int argc, char** argv)
{
	if(!data) return 1;
	if(argc < 2) return 1;

	memset((void*)data, 0x00, sizeof(paramData));

	for(int i = 1; i < argc - 1; i++)
	{
		if(strncmp(argv[i], "-key=", 5) == 0)
		{
			char* arg = argv[i] + 5;		
			data->keystore = fopen(arg, "rb");
		}
		else if(strncmp(argv[i], "-target=", 8) == 0)
		{
			char* arg = argv[i] + 8;
			if(strncmp(arg, "0x", 2) == 0) data->payloadTarget = strtol(arg+2, NULL, 16);
			else if(isHexString(arg)) data->payloadTarget = strtol(arg, NULL, 16);
			else data->payloadTarget = strtol(arg, NULL, 10);
		}
		else if(strncmp(argv[i], "-precision=", 11) == 0)
		{
			char* arg = argv[i] + 11;
			if(strncmp(arg, "0x", 2) == 0) data->payloadPrecision = strtol(arg+2, NULL, 16);
			else if(isHexString(arg)) data->payloadPrecision = strtol(arg, NULL, 16);
			else data->payloadPrecision = strtol(arg, NULL, 10);		
		}
		else if(strncmp(argv[i], "-limit=", 7) == 0)
		{
			char* arg = argv[i] + 7;
			if(strncmp(arg, "0x", 2) == 0) data->limit = strtol(arg+2, NULL, 16);
			else if(isHexString(arg)) data->limit = strtol(arg, NULL, 16);
			else data->limit = strtol(arg, NULL, 10);		
		}
		else
		{
			printf("Unknown parameter --> %s\n\n", argv[i]);
			return 1;
		}
	}

	FILE* file = fopen(argv[argc - 1], "rb");
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
			data->arm9Binary = (u8*) malloc (size);
			data->arm9BinarySize = size;
			if(!data->payloadTarget) data->payloadTarget  = 0x08006000 + data->arm9BinarySize;
			if(!data->payloadPrecision) data->payloadPrecision = 0x1000;
			fseek(file, off, 0);
			fread(data->arm9Binary, 1, data->arm9BinarySize, file);
			fclose(file);
			return 0;
		}
		fclose(file);
	}
	return 1;
}

void printUsage()
{
	printf("Usage   : %s [options] <firm_file_path>\n", APPNAME);
	printf("Options :\n");
	printf("    -target=<addr>    : Specify the target address you want the\n");
	printf("                        exploit to jump on. Both Dec and Hex values\n");
	printf("                        are accepted (Hex need the 0x prefix).\n");
	printf("    -precision=<addr> : Specify the precision of the area the exploit\n");
	printf("                        should jump on. Both Dec and Hex values are\n");
	printf("                        accepted (Hex need the 0x prefix).\n");
	printf("    -key=<key_file>   : Specify an external binary file which contains\n");
	printf("                        one or more 0x10 bytes-long AES keys to try.\n");
	printf("    -limit=num        : Specify the max number of attempts the\n");
	printf("                        bruteforcer have to do. Both Dec and Hex\n");
	printf("                        value sare accepted (Hex need the 0x prefix).\n");
	exit(-1);
}