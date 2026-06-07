#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* ── Output types ─────────────────────────────────────────────────────────── */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OOB  0x20
#define CALLBACK_ERROR       0x0d

/* ── Output ───────────────────────────────────────────────────────────────── */
DECLSPEC_IMPORT void   BeaconOutput(int type, char* data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, char* fmt, ...);

/* ── Argument parser ──────────────────────────────────────────────────────── */
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void   BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT char*  BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT int    BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short  BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int    BeaconDataLength(datap* parser);

/* ── Format builder ───────────────────────────────────────────────────────── */
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} formatp;

DECLSPEC_IMPORT void   BeaconFormatAlloc(formatp* format, int maxsz);
DECLSPEC_IMPORT void   BeaconFormatReset(formatp* format);
DECLSPEC_IMPORT void   BeaconFormatFree(formatp* format);
DECLSPEC_IMPORT void   BeaconFormatAppend(formatp* format, char* text, int len);
DECLSPEC_IMPORT void   BeaconFormatPrintf(formatp* format, char* fmt, ...);
DECLSPEC_IMPORT char*  BeaconFormatToString(formatp* format, int* size);
DECLSPEC_IMPORT void   BeaconFormatInt(formatp* format, int value);

/* ── Utility ──────────────────────────────────────────────────────────────── */
DECLSPEC_IMPORT BOOL   BeaconIsAdmin(void);
DECLSPEC_IMPORT BOOL   toWideChar(char* src, wchar_t* dst, int max);
