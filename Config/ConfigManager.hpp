#pragma once
#include <iostream>

class ConfigManager {
public:
	ConfigManager();

	static bool isEnabled;
	static std::string keybind;

	static std::string ParseUsername(bool game = false);
	static std::string ParsePassword();

	static void ChangeState(std::string keybind, bool isEnabled);
	static void Parse();
private:
	static std::string UnlimitedCPS;
	static std::string Loader;
	static std::string Game;
};