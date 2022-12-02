#pragma once

#include "PEHeader.h"
#include "PEHeaderException.h"

void PEHeader::loadPEheader() {

	//offset by 4 because we skip 'PE\0\0' string to get to the real deal. Maybe later check if we actually find that string to confirm that we have a PE Header
	DWORD entry = this->getPEHeaderEntry() + 4;


	this->binfile.seekg(entry);
	BYTE peHeader_chunks[sizeof(this->pe_file_header)];

	for (int i = 0; this->binfile.tellg() < entry + sizeof this->pe_file_header; i++) {

		peHeader_chunks[i] = (BYTE)this->binfile.get();
	}

	memcpy(&(this->pe_file_header), peHeader_chunks, sizeof this->pe_file_header);
	
	loadPEOptionalHeader();
}

void PEHeader::loadPEOptionalHeader() {
	DWORD entry = this->binfile.tellg();

	BYTE peOptHeader_chunks[sizeof(this->pe_optional_header)];

	for (int i = 0; this->binfile.tellg() < entry + sizeof this->pe_optional_header; i++) {
		peOptHeader_chunks[i] = (BYTE)this->binfile.get();
	}

	memcpy(&(this->pe_optional_header), peOptHeader_chunks, sizeof this->pe_optional_header);

	loadPESectionlHeaders();
}

void PEHeader::loadPESectionlHeaders() {
	DWORD entry = this->binfile.tellg();
	IMAGE_SECTION_HEADER section_header;

	BYTE peSecHeader_chunks[sizeof(section_header)];

	for (int j = 0; j < this->pe_file_header.NumberOfSections; j++, entry = this->binfile.tellg()) {
		for (int i = 0; this->binfile.tellg() < entry + sizeof section_header; i++) {
			peSecHeader_chunks[i] = (BYTE)this->binfile.get();
		}

		memcpy(&(section_header), peSecHeader_chunks, sizeof section_header);
		this->pe_section_headers.push_back(section_header);
		
	}

	loadPESections();

}

void PEHeader::loadPESections() {

	//TODO: IDK how to load sections the best way yet

	/*for (auto x : this->pe_section_headers) {
		
		this->binfile.seekg(x.VirtualAddress);
		DWORD entry = this->binfile.tellg();
		int i = 0;

		for (auto &p : this->sections) {
			
			p.second.push_back((BYTE)this->binfile.get());
		}

	}*/
}

std::string PEHeader::machineDetails() {

	for (auto const &p : this->machineFlags) {
		if (p.first == this->pe_file_header.Machine) {
			return p.second;
		}
	}

}

std::vector<std::string> PEHeader::characteristicDetails() {
	WORD characteristics_tmp = this->pe_file_header.Characteristics;
	std::vector<std::string> flag_gathering;

	for (auto const& p : this->characteristicFlags) {
		if (p.first & characteristics_tmp) {
			characteristics_tmp - p.first;
			flag_gathering.push_back(p.second);
		}
	}

	return flag_gathering;
}

DWORD PEHeader::getPEHeaderEntry() {
	this->binfile.seekg(0x3c);
	BYTE addr_chunks[4];
	DWORD addr;

	for (int i = 0; this->binfile.tellg() < 0x3c + sizeof addr; i++) {
		addr_chunks[i] = (BYTE)this->binfile.get();
	}

	memcpy(&addr, addr_chunks, sizeof addr);

	return addr;
}

//losing the datatypes of the different parts of the header by forcing a cast to ULONGLONG
std::vector<ULONGLONG> PEHeader::outputListPEHeader() {
	std::vector<ULONGLONG> v = {
		this->pe_file_header.Machine,
		this->pe_file_header.NumberOfSections,
		this->pe_file_header.TimeDateStamp,
		this->pe_file_header.PointerToSymbolTable,
		this->pe_file_header.NumberOfSymbols,
		this->pe_file_header.SizeOfOptionalHeader,
		this->pe_file_header.Characteristics
	};

	return v;
}

//losing the datatypes of the different parts of the header by forcing a cast to ULONGLONG
std::vector<ULONGLONG> PEHeader::outputListPEOptHeader() {
	std::vector<ULONGLONG> v = {
		this->pe_optional_header.Magic,
		this->pe_optional_header.MajorLinkerVersion,
		this->pe_optional_header.MinorLinkerVersion,
		this->pe_optional_header.SizeOfCode,
		this->pe_optional_header.SizeOfInitializedData,
		this->pe_optional_header.SizeOfUninitializedData,
		this->pe_optional_header.AddressOfEntryPoint,
		this->pe_optional_header.BaseOfCode,
		this->pe_optional_header.ImageBase,
		this->pe_optional_header.SectionAlignment,
		this->pe_optional_header.FileAlignment,
		this->pe_optional_header.MajorOperatingSystemVersion,
		this->pe_optional_header.MinorOperatingSystemVersion,
		this->pe_optional_header.MajorImageVersion,
		this->pe_optional_header.MinorImageVersion,
		this->pe_optional_header.MajorSubsystemVersion,
		this->pe_optional_header.MinorSubsystemVersion,
		this->pe_optional_header.Win32VersionValue,
		this->pe_optional_header.SizeOfImage,
		this->pe_optional_header.SizeOfHeaders,
		this->pe_optional_header.CheckSum,
		this->pe_optional_header.Subsystem,
		this->pe_optional_header.DllCharacteristics,
		this->pe_optional_header.SizeOfStackReserve,
		this->pe_optional_header.SizeOfStackCommit,
		this->pe_optional_header.SizeOfHeapReserve,
		this->pe_optional_header.SizeOfHeapCommit,
		this->pe_optional_header.LoaderFlags,
		this->pe_optional_header.NumberOfRvaAndSizes,
		
	};

	return v;
}

PEHeader::PEHeader(std::string file_name) {
	this->file_name = file_name;

	this->binfile.open(this->file_name, std::ios::binary);
	binfile.seekg(0, std::ios::end);
	this->file_size = binfile.tellg();
	binfile.seekg(0, std::ios::beg);

	loadPEheader();

	this->binfile.close();

}