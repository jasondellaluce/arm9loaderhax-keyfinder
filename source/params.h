#pragma once

#include "types.h"
#include <stdio.h>

typedef struct
{
	u32 payloadTarget;
	u32 payloadPrecision;
	u8* arm9Binary;
	u32 arm9BinarySize;
	u32 limit;
	FILE* keystore;
} paramData;

int parseParams(paramData* data, int argc, char** argv);
void printUsage();