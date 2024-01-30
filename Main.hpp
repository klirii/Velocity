#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <random>
#include <nlohmann/json.hpp>

#include "JavaHook.hpp"
#include "JLI.hpp"

#include "Config.hpp"
#include "Config/ConfigManager.hpp"

#include "RestAPI/Core/Client.hpp"
#include "RestAPI/Utils/Utils.hpp"

#include "Utils/Hashes.hpp"

#define DLL_VIMEWORLD_ATTACH 0x888

#define DEBUG(format, ...) printf("[!] " format "\n", __VA_ARGS__);
#define M_PI 3.14159265358979323846

using json = nlohmann::json;
RestAPI::Client client;