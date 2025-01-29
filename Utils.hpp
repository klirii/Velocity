#include <Windows.h>
#include <iostream>

//#define DEBUG(format, ...) printf("[!] " format "\n", __VA_ARGS__);
#define DEBUG(format, ...)

std::string BytesToHexStr(BYTE* bytes, size_t size) {
	// ������������ ����� ������: 3 ������� (��� ��� ����� � ������) �� ������ ����, ����� 1 ������ �� �����.
	std::string result;
	result.reserve(size * 3); // �����������: ����������� ������ �����.

	for (size_t i = 0; i < size; ++i) {
		char buffer[3]; // ��� ���� �������� + '\0'.
		std::snprintf(buffer, sizeof(buffer), "%02X", bytes[i]);
		result.append(buffer);

		// ��������� ������, ���� ��� �� ��������� ����.
		if (i < size - 1) result += ' ';
	}

	return result;
}