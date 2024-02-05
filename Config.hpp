#pragma once
#include <string>
#include <fstream>
#include <iostream>
#include <mutex>

#include "Utils/Keybind.hpp"
#include "Utils/ErrorHandler.hpp"

namespace Config {
	std::string path;
	std::mutex config_lock;

	void Rewrite(
		const int horizontal_min,
		const int horizontal_max,
		const int vertical_min,
		const int vertical_max,
		const bool only_forward,
		const bool only_moving,
		const bool enabled
	) {
		std::lock_guard<std::mutex> lock(config_lock);

		std::ifstream icfg(path);
		std::string keybind;

		if (icfg.is_open()) {
			for (std::string param, value; std::getline(icfg, param, '=') && std::getline(icfg, value); ) {
				if (param == "keybind")
					keybind = value;
			}

			icfg.close();
		}
		else {
			MessageBoxA(Utils::ErrorHandler::window, "Ошибка чтения файла!", "Velocity", MB_ICONERROR);
		}

		std::ofstream ocfg(path, std::ios::trunc);
		if (ocfg.is_open()) {
			ocfg << "horizontal_min=" << horizontal_min << std::endl;
			ocfg << "horizontal_max=" << horizontal_max << std::endl;
			ocfg << "vertical_min=" << vertical_min << std::endl;
			ocfg << "vertical_max=" << vertical_max << std::endl;
			ocfg << "only_forward=" << (only_forward ? "true" : "false") << std::endl;
			ocfg << "only_moving=" << (only_moving ? "true" : "false") << std::endl;
			ocfg << "enabled=" << (enabled ? "true" : "false") << std::endl;
			ocfg << "keybind=" << keybind;
		}
		else {
			MessageBoxA(Utils::ErrorHandler::window, "Ошибка записи файла!", "Velocity", MB_ICONERROR);
		}
	}

	void Read(
		int& horizontal_min,
		int& horizontal_max,
		int& vertical_min,
		int& vertical_max,
		int& keycode,
		bool& only_forward,
		bool& only_moving,
		bool& enabled
	) {
		std::lock_guard<std::mutex> lock(config_lock);

		std::ifstream cfg(path);
		if (cfg.is_open()) {
			for (std::string param, value; std::getline(cfg, param, '=') && std::getline(cfg, value); ) {
				if (param == "horizontal_min") horizontal_min = atoi(value.c_str());
				else if (param == "horizontal_max") horizontal_max = atoi(value.c_str());
				else if (param == "vertical_min") vertical_min = atoi(value.c_str());
				else if (param == "vertical_max") vertical_max = atoi(value.c_str());
				else if (param == "only_forward") only_forward = (value == "true" ? true : false);
				else if (param == "only_moving") only_moving = (value == "true" ? true : false);
				else if (param == "enabled") enabled = (value == "true" ? true : false);
				else if (param == "keybind") keycode = Keybind::GetVirtualKeyCodeByKeyName(value);
			}
		}
		else {
			MessageBoxA(Utils::ErrorHandler::window, "Ошибка чтения файла!", "Velocity", MB_ICONERROR);
		}
	}
}