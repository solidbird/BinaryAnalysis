#pragma once
#include <iostream>

class UndetectedPEHeaderException : public std::exception {
public:
	std::string msg(std::string path);
};

class HeaderSizeException : public std::exception {
public:
	std::string msg(unsigned long sizeOfHeader);

};