// BinaryAnalysis.cpp : Diese Datei enthält die Funktion "main". Hier beginnt und endet die Ausführung des Programms.
//
#pragma once
#include <iostream>
#include <fstream>
#include  <iomanip>
#include "PEHeader.h"

void outputDataDictonary(PEHeader &peh) {
	std::string dataDirNames[] = {
		"Export Directory [.edata]",
		"Import Directory [parts of .idata]",
		"Resource Directory [.rsrc]",
		"Exception Directory [.pdata]",
		"Security Directory",
		"Base Relocation Directory [.reloc]",
		"Debug Directory",
		"Description Directory",
		"Special Directory",
		"Thread Storage Directory [.tls]",
		"Load Configuration Directory",
		"Bound Import Directory",
		"Import Address Table Directory",
		"Delay Import Directory",
		"CLR Runtime Header",
		"Reserved"
	};
	

	int i = 0;
	for (auto x : peh.pe_optional_header.DataDirectory) {
		
		if (x.Size == 0) {
			i++;
			continue;
		}

		printf("%d: Size: %x, VirtualAddress: %x\n", i, x.Size, x.VirtualAddress);
		i++;

	}
}

int main() {
	PEHeader peh = PEHeader("C:\\Users\\Ich\\source\\repos\\BinaryAnalysis\\x64\\Debug\\calc.exe");


	printf("\nPE HEADER:\nMachine: %.2x\n"
		"NumberOfSections: %.2x\n"
		"TimeDateStamp : %.2x\n"
		"PointerToSymbolTable : %.2x\n"
		"NumberOfSymbols : %.2x\n"
		"SizeOfOptionalHeader : %.2x\n"
		"Characteristics : %.2x\n",
		(peh.pe_file_header.Machine),
		(peh.pe_file_header.NumberOfSections),
		(peh.pe_file_header.TimeDateStamp),
		(peh.pe_file_header.PointerToSymbolTable),
		(peh.pe_file_header.NumberOfSymbols),
		(peh.pe_file_header.SizeOfOptionalHeader),
		(peh.pe_file_header.Characteristics));

	std::cout << peh.pe_file_header.TimeDateStamp << std::endl;

	//std::cout << "MAGIC:" << std::hex << peh.pe_optional_header.Magic << std::endl;

	/*std::cout << "0x" << std::setfill('0') << std::setw(sizeof peh.pe_file_header.Machine * 2) << std::hex << peh.pe_file_header.Machine << std::endl;
	std::cout << "0x" << std::setfill('0') << std::setw(sizeof peh.pe_file_header.NumberOfSections * 2) << std::hex << peh.pe_file_header.NumberOfSections << std::endl;
	std::cout << "0x" << std::setfill('0') << std::setw(sizeof peh.pe_file_header.TimeDateStamp * 2) << std::hex << peh.pe_file_header.TimeDateStamp << std::endl;
	std::cout << "0x" << std::setfill('0') << std::setw(sizeof peh.pe_file_header.PointerToSymbolTable * 2) << std::hex << peh.pe_file_header.PointerToSymbolTable << std::endl;
	std::cout << "0x" << std::setfill('0') << std::setw(sizeof peh.pe_file_header.NumberOfSymbols * 2) << std::hex << peh.pe_file_header.NumberOfSymbols << std::endl;
	std::cout << "0x" << std::setfill('0') << std::setw(sizeof peh.pe_file_header.SizeOfOptionalHeader * 2) << std::hex << peh.pe_file_header.SizeOfOptionalHeader << std::endl;*/

	printf("\nPE OPT HEADER:\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n"
		, peh.pe_optional_header.Magic
		, peh.pe_optional_header.MajorLinkerVersion
		, peh.pe_optional_header.MinorLinkerVersion
		, peh.pe_optional_header.SizeOfCode
		, peh.pe_optional_header.SizeOfInitializedData
		, peh.pe_optional_header.SizeOfUninitializedData
		, peh.pe_optional_header.AddressOfEntryPoint
		, peh.pe_optional_header.BaseOfCode
		, peh.pe_optional_header.ImageBase
		, peh.pe_optional_header.SectionAlignment
		, peh.pe_optional_header.FileAlignment
		, peh.pe_optional_header.MajorOperatingSystemVersion
		, peh.pe_optional_header.MinorOperatingSystemVersion
		, peh.pe_optional_header.MajorImageVersion
		, peh.pe_optional_header.MinorImageVersion
		, peh.pe_optional_header.MajorSubsystemVersion
		, peh.pe_optional_header.MinorSubsystemVersion
		, peh.pe_optional_header.Win32VersionValue
		, peh.pe_optional_header.SizeOfImage
		, peh.pe_optional_header.SizeOfHeaders
		, peh.pe_optional_header.CheckSum
		, peh.pe_optional_header.Subsystem
		, peh.pe_optional_header.DllCharacteristics
		, peh.pe_optional_header.SizeOfStackReserve
		, peh.pe_optional_header.SizeOfStackCommit
		, peh.pe_optional_header.SizeOfHeapReserve
		, peh.pe_optional_header.SizeOfHeapCommit
		, peh.pe_optional_header.LoaderFlags
		, peh.pe_optional_header.NumberOfRvaAndSizes);

	
	std::cout << "\nPE SECTION HEADERS:" << std::endl;
	for (auto x : peh.pe_section_headers) {
		//std::cout << x.Name << ":" << std::hex << x.Characteristics << std::endl;
		printf("%s: %x\n", x.Name, x.Characteristics);
	}
	
	outputDataDictonary(peh);

	/*std::cout << "MACHINE: " << peh.machineDetails() << std::endl;
	std::cout << "CHARACTERISTICS: ";
	for (auto x : peh.characteristicDetails()) {
		std::cout << "\t\n" << x;
	}*/
}