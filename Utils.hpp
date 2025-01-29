#include <Windows.h>
#include <iostream>

//#define DEBUG(format, ...) printf("[!] " format "\n", __VA_ARGS__);
#define DEBUG(format, ...)

std::string BytesToHexStr(BYTE* bytes, size_t size) {
	// Максимальная длина строки: 3 символа (два для байта и пробел) на каждый байт, минус 1 пробел на конце.
	std::string result;
	result.reserve(size * 3); // Оптимизация: резервируем память сразу.

	for (size_t i = 0; i < size; ++i) {
		char buffer[3]; // Для двух символов + '\0'.
		std::snprintf(buffer, sizeof(buffer), "%02X", bytes[i]);
		result.append(buffer);

		// Добавляем пробел, если это не последний байт.
		if (i < size - 1) result += ' ';
	}

	return result;
}