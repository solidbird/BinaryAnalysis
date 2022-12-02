#include "PEHeaderException.h"

std::string UndetectedPEHeaderException::msg(std::string path) {
	return "Could not find PEHeader in binary: " + path;
}

std::string HeaderSizeException::msg(unsigned long sizeOfHeader) {
	return "Header size was too long: " + sizeOfHeader;
}

