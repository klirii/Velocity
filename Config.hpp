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

#define GET_INT_VAL(stream, line, param) {	\
	if (line == #param) {					\
		std::getline(stream, line);			\
		param = atoi(line.c_str());			\
	}										\
}											\

#define GET_BOOL_VAL(stream, line, param) {		\
	if (line == #param) {						\
		std::getline(stream, line);				\
		param = line == "true" ? true : false;	\
	}											\
}												\

#define GET_STRING_VAL(stream, line, param) {	\
	if (line == #param) {						\
		std::getline(stream, line);				\
		param = line;                           \
	}											\
}                                               \

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
			for (std::string line; std::getline(cfg, line, '='); ) {
				GET_INT_VAL(cfg, line, horizontal_min);
				GET_INT_VAL(cfg, line, horizontal_max);
				GET_INT_VAL(cfg, line, vertical_min);
				GET_INT_VAL(cfg, line, vertical_max);

				GET_BOOL_VAL(cfg, line, only_forward);
				GET_BOOL_VAL(cfg, line, only_moving);
				GET_BOOL_VAL(cfg, line, enabled);

				std::string keybind;
				GET_STRING_VAL(cfg, line, keybind);
				keycode = Keybind::GetVirtualKeyCodeByKeyName(keybind);
			}
		}
		else {
			MessageBoxA(Utils::ErrorHandler::window, "Ошибка чтения файла!", "Velocity", MB_ICONERROR);
		}
	}
}