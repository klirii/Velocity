#define _CRT_SECURE_NO_WARNINGS
#include "ConfigManager.hpp"

#include <fstream>
#include <codecvt>
#include <string>

#include <StringUtils.h>
#include <StringUtils.cpp>

#pragma warning(disable:4244)

bool ConfigManager::isEnabled = false;
std::string ConfigManager::keybind = "";

std::string ConfigManager::UnlimitedCPS = "";
std::string ConfigManager::Loader = "";
std::string ConfigManager::Game = "";

ConfigManager::ConfigManager() {
	UnlimitedCPS = std::string(getenv("APPDATA")) + "\\.vimeworld\\minigames\\UnlimitedCPS.ini";
	isEnabled = true;
	keybind = "F8";

	struct _stat fiBuf;
	if (_stat(UnlimitedCPS.c_str(), &fiBuf) == -1) {
		std::wofstream config(UnlimitedCPS);
		config.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));

		config << L"keybind=F8\n";
		config << L"enabled=true";
		config.close();
	}
}

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

void ConfigManager::ChangeState(std::string keybind, bool isEnabled) {
	std::wofstream config(UnlimitedCPS, std::ios::trunc);
	config.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));

	config << L"keybind=" << std::wstring(keybind.begin(), keybind.end()) << std::endl;
	config << L"enabled=" << (isEnabled ? L"true" : L"false");
	config.close();
}

void ConfigManager::Parse() {
	std::string line;
	std::wstring wline;
	char* lineParts[2];

	std::wifstream config(UnlimitedCPS);
	config.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));

	while (std::getline(config, wline)) {
		line = std::string(wline.begin(), wline.end());
		if (line.find("keybind") != string::npos) {
			StringUtils::split(line.c_str(), '=', lineParts);
			ConfigManager::keybind = StringUtils::toUpper(lineParts[1]);;
		}
		else if (line.find("enabled") != string::npos) {
			StringUtils::split(line.c_str(), '=', lineParts);
			ConfigManager::isEnabled = strcmp(lineParts[1], "true") == 0 ? true : false;
		}
	}
}