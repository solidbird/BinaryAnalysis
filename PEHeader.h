#include <iostream>
#include <fstream>
#include <oaidl.h>
#include <vector>
#include <map>

/*
	TODO Already implemented a header that has IMAGE_OPTIONAL_HEADER64 in it and other fields in it like 'machine'
	https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
	*/


#define IMAGE_FILE_AGGRESSIVE_WS_TRIM 0x0010

class PEHeader
{
protected:
	
	const std::map<WORD, std::string> characteristicFlags{
		{IMAGE_FILE_RELOCS_STRIPPED, "IMAGE_FILE_RELOCS_STRIPPED"},
		{IMAGE_FILE_EXECUTABLE_IMAGE, "IMAGE_FILE_EXECUTABLE_IMAGE"},
		{IMAGE_FILE_LINE_NUMS_STRIPPED, "IMAGE_FILE_LINE_NUMS_STRIPPED"},
		{IMAGE_FILE_LOCAL_SYMS_STRIPPED, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"},
		{IMAGE_FILE_AGGRESSIVE_WS_TRIM, "IMAGE_FILE_AGGRESSIVE_WS_TRIM"},
		{IMAGE_FILE_LARGE_ADDRESS_AWARE, "IMAGE_FILE_LARGE_ADDRESS_AWARE"},
		{IMAGE_FILE_BYTES_REVERSED_LO, "IMAGE_FILE_BYTES_REVERSED_LO"},
		{IMAGE_FILE_32BIT_MACHINE, "IMAGE_FILE_32BIT_MACHINE"},
		{IMAGE_FILE_DEBUG_STRIPPED, "IMAGE_FILE_DEBUG_STRIPPED"},
		{IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"},
		{IMAGE_FILE_NET_RUN_FROM_SWAP, "IMAGE_FILE_NET_RUN_FROM_SWAP"},
		{IMAGE_FILE_SYSTEM, "IMAGE_FILE_SYSTEM"},
		{IMAGE_FILE_DLL, "IMAGE_FILE_DLL"},
		{IMAGE_FILE_UP_SYSTEM_ONLY, "IMAGE_FILE_UP_SYSTEM_ONLY"},
		{IMAGE_FILE_BYTES_REVERSED_HI, "IMAGE_FILE_BYTES_REVERSED_HI"}
	};

	const std::map<WORD, std::string> machineFlags{
		{IMAGE_FILE_MACHINE_ALPHA,"Alpha_AXP"},
		{IMAGE_FILE_MACHINE_ALPHA64,"ALPHA64"},
		{IMAGE_FILE_MACHINE_AXP64,"AXP64"},
		{IMAGE_FILE_MACHINE_AM33,"AM33"},
		{IMAGE_FILE_MACHINE_AMD64,"AMD64 (K8)"},
		{IMAGE_FILE_MACHINE_ARM,"ARM (Little-Endian)"},
		{IMAGE_FILE_MACHINE_ARM64,"ARM64 (Little-Endian)"},
		{IMAGE_FILE_MACHINE_ARMNT,"ARM Thunmb-2 (Little - Endian)"},
		{IMAGE_FILE_MACHINE_CEE,"CEE"},
		{IMAGE_FILE_MACHINE_CEF,"CEF"},
		{IMAGE_FILE_MACHINE_EBC,"EFI Byte Code"},
		{IMAGE_FILE_MACHINE_I386,"Intel 386"},
		{IMAGE_FILE_MACHINE_IA64,"Intel 64"},
		{IMAGE_FILE_MACHINE_M32R,"M32R (Little-Endian)"},
		{IMAGE_FILE_MACHINE_MIPS16,"MIPS_16"},
		{IMAGE_FILE_MACHINE_MIPSFPU,"MIPS_FPU"},
		{IMAGE_FILE_MACHINE_MIPSFPU16,"MIPS_FPU16"},
		{IMAGE_FILE_MACHINE_POWERPC,"IBM Power-PC (Little_Endian)"},
		{IMAGE_FILE_MACHINE_POWERPCFP,"PowerPCFP"},
		{IMAGE_FILE_MACHINE_R10000,"MIPS (Little-Endian) R10000"},
		{IMAGE_FILE_MACHINE_R3000,"MIPS (0x160 Little-Endian)"},
		{IMAGE_FILE_MACHINE_R4000,"MIPS (Little-Endian) R4000"},
		{IMAGE_FILE_MACHINE_SH3,"SH3 (Little-Endian)"},
		{IMAGE_FILE_MACHINE_SH3DSP,"SH3DSP"},
		{IMAGE_FILE_MACHINE_SH3E,"SH3E (Little-Endian)"},
		{IMAGE_FILE_MACHINE_SH4,"SH4 (Little-Endian)"},
		{IMAGE_FILE_MACHINE_SH5,"SH5"},
		{IMAGE_FILE_MACHINE_TARGET_HOST,"TARGET_HOST"},
		{IMAGE_FILE_MACHINE_THUMB,"ARM Thumb/Thumb2 (Little Endian)"},
		{IMAGE_FILE_MACHINE_TRICORE,"Infineon"},
		{IMAGE_FILE_MACHINE_UNKNOWN,"UNKNOWN"},
		{IMAGE_FILE_MACHINE_WCEMIPSV2,"MIPS WCE v2 (Little Endian)"}
	};

public:
	std::string file_name;
	int file_size;
	std::ifstream binfile;

	IMAGE_FILE_HEADER pe_file_header;
	IMAGE_OPTIONAL_HEADER64 pe_optional_header;
	std::vector<IMAGE_SECTION_HEADER> pe_section_headers;
	std::map<int, std::vector<BYTE>> sections;

	

private:
	void loadPEheader();
	void loadPEOptionalHeader();
	void loadPESectionlHeaders();
	void loadPESections();

public:
	PEHeader(std::string file_name);
	DWORD getPEHeaderEntry();

	std::string machineDetails();
	std::vector<std::string> characteristicDetails();

	//TODO: Make struct header to vector and force type to ULONGLONG
	std::vector<ULONGLONG> outputListPEHeader();
	std::vector<ULONGLONG> outputListPEOptHeader();

};