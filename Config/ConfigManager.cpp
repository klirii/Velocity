#define _CRT_SECURE_NO_WARNINGS
#include "ConfigManager.hpp"

#include <fstream>
#include <codecvt>
#include <string>

#include <StringUtils.h>
#include <StringUtils.cpp>

#pragma warning(disable:4244)

std::string ConfigManager::Loader = "";
std::string ConfigManager::Game = "";

std::string ConfigManager::ParseUsername(bool game) {
	if (!game) {
		Loader = std::string(getenv("APPDATA")) + "\\.vimeworld\\jre-x64\\lib\\security\\java8.security";

		char username[12];
		std::ifstream(Loader).getline(username, 12);

		if (std::string(username).empty()) return "";
		return std::string(username);
	}
	else {
		Game = std::string(getenv("APPDATA")) + "\\.vimeworld\\config";

		std::wstring username;
		std::wifstream config(Game);

		config.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));
		for (uint8_t i = 0; i < 2; i++) std::getline(config, username);

		char* lineParts[2];
		StringUtils::split(std::string(username.begin(), username.end()).c_str(), ':', lineParts);

		if (std::string(lineParts[1]).empty()) return "";
		return std::string(lineParts[1]);
	}
}

std::string ConfigManager::ParsePassword() {
	std::ifstream config(Loader);
	std::string password;

	for (uint8_t i = 0; i < 2; i++)
		std::getline(config, password);

	return password;
}