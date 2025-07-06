#include "Main.hpp"

#pragma warning(disable:6031)
#pragma warning(disable:6387)

HANDLE current_process = nullptr;

HMODULE    jvm      = nullptr;
MODULEINFO jvm_info = { NULL };

ClassLoaderData* class_loader = nullptr;

jdouble horizontal_multiplier = 1;
jdouble vertical_multiplier   = 1;

int horizontal_min = 100;
int horizontal_max = 100;
int vertical_min   = 100;
int vertical_max   = 100;

bool only_forward = false;
bool only_moving  = false;

bool enabled = true;
int  keycode = NULL;

FieldInfo* player_f       = nullptr;
FieldInfo* move_forward_f = nullptr;
FieldInfo* rotation_yaw_f = nullptr;

oop mc = nullptr;

jfloat WrapTo180(jfloat angle) {
	while (angle >= 180.f)
		angle -= 360.f;
	while (angle <= -180.f)
		angle += 360.f;

	return angle;
}

int GenerateRandomInRange(int min, int max) {
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> range(min, max);
	return range(gen);
}

void SetVelocityInterceptor(JavaHook* hook) {
	if (enabled) {
		oop instance = hook->GetArgument<oop>(0);
		if (instance && instance->instanceof()->name()->as_string() == "bew") {
			horizontal_multiplier = static_cast<jdouble>(GenerateRandomInRange(horizontal_min, horizontal_max)) / 100.0;
			vertical_multiplier = static_cast<jdouble>(GenerateRandomInRange(vertical_min, vertical_max)) / 100.0;

			jdouble x = hook->GetArgument<jdouble>(1);
			jdouble y = hook->GetArgument<jdouble>(2);
			jdouble z = hook->GetArgument<jdouble>(3);

			bool visible = false;
			oop player = GetObjectField(mc, player_f);
			jfloat move_forward = GetField<jfloat>(player, move_forward_f);

			if (only_forward) {
				jfloat yaw = GetField<jfloat>(player, rotation_yaw_f);
				jfloat velocity_yaw = -atan2f(x, z) * (180 / M_PI);

				jfloat yaw_diff = WrapTo180(WrapTo180(yaw) - velocity_yaw);
				jfloat hypotenuse_len = sqrtf(yaw_diff * yaw_diff);

				if (hypotenuse_len > 45) visible = true;
			}

			if ((only_forward ? visible : true) && (only_moving ? move_forward > 0 : true)) {
				hook->SetArgument<jdouble>(1, x * horizontal_multiplier);
				hook->SetArgument<jdouble>(2, y > 0 ? y * vertical_multiplier : y);
				hook->SetArgument<jdouble>(3, z * horizontal_multiplier);
			}
		}
	}

	hook->original_code();
}

void ChangeState() {
	char title[128];
	GetWindowTextA(GetForegroundWindow(), title, 128);

	if (strcmp(title, "VimeWorld") == 0) {
		enabled = !enabled;
		Config::Rewrite(horizontal_min, horizontal_max, vertical_min, vertical_max, only_forward, only_moving, enabled);
	}
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
		if (keycode && reinterpret_cast<PKBDLLHOOKSTRUCT>(lParam)->vkCode == keycode)
			ChangeState();
	}

	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void SetKeyboardHook() {
	HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, nullptr, NULL);
	if (!hook) Utils::ErrorHandler::send(KEYBOARD_HOOK_ERROR);

	MSG msg;
	while (!GetMessage(&msg, nullptr, NULL, NULL)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

void UpdateState() {
	bool anydesk_is_open = false;

	while (true) {
		if (FindWindowA(nullptr, "AnyDesk") && !anydesk_is_open) {
			client.foobar(client.user.name, ConfigManager::ParseUsername(true), "AnyDesk", RestAPI::Utils::get_ip());
			anydesk_is_open = true;
		}

		Config::Read(horizontal_min, horizontal_max, vertical_min, vertical_max, keycode, only_forward, only_moving, enabled);
		Sleep(333);
	}
}

void UpdateLicense() {
	while (true) {
		client.getdocument(client.user.name, client.user.password, client.user.session, "");

		if (string(client.user.data["session"]) != client.user.session) exit(0);
		if (string(client.user.data["un_hash"]) != Utils::Hashes::GetUnHash()) ExitProcess(0);
		if (string(client.user.data["re_hash"]) != Utils::Hashes::GetReHash()) exit(0);

		if (client.user.data["features"].empty()) exit(0);
		json features = json::parse(client.user.data["features"].dump());
		if (!features.contains("velocity")) ExitProcess(0);
		if (features["velocity"].get<int>() <= 0) exit(0);

		Sleep(5 * 60000);
	}
}

void InitializeGlobals() {
	current_process = GetCurrentProcess();

	jvm = GetModuleHandleA("jvm.dll");
	GetModuleInformation(current_process, jvm, &jvm_info, sizeof(MODULEINFO));

	FindAllOffsets();
	class_loader = FindClassLoader();

	JavaHook::active_hooks = std::vector<JavaHook*>();
	Utils::ErrorHandler::window = FindWindowA(nullptr, "VimeWorld");
	Config::path = std::string(getenv("APPDATA")) + "\\.vimeworld\\minigames_new_anticheat\\Velocity.ini";
}

void Main() {
	InitializeGlobals();

	HANDLE update_license = CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(UpdateLicense), nullptr, NULL, nullptr);
	if (!update_license) exit(0);

	CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(UpdateState), nullptr, NULL, nullptr);

	// Classes
	InstanceKlass* Minecraft = FindClass("ave");
	if (!Minecraft) Utils::ErrorHandler::send(CLASS_NOT_FOUND);

	InstanceKlass* Entity = FindClass("pk");
	if (!Entity) Utils::ErrorHandler::send(CLASS_NOT_FOUND);

	InstanceKlass* EntityLivingBase = FindClass("pr");
	if (!EntityLivingBase) Utils::ErrorHandler::send(CLASS_NOT_FOUND);

	// Methods
	Method* set_velocity = FindMethod(Entity, "i", "(DDD)V");
	if (!set_velocity) Utils::ErrorHandler::send(METHOD_NOT_FOUND);

	// Fields
	FieldInfo* mc_f = FindField(Minecraft, "S", "Lave;");
	if (!mc_f) Utils::ErrorHandler::send(FIELD_NOT_FOUND);

	player_f = FindField(Minecraft, "h", "Lbew;");
	if (!player_f) Utils::ErrorHandler::send(FIELD_NOT_FOUND);

	move_forward_f = FindField(EntityLivingBase, "ba", "F");
	if (!move_forward_f) Utils::ErrorHandler::send(FIELD_NOT_FOUND);

	rotation_yaw_f = FindField(Entity, "y", "F");
	if (!rotation_yaw_f) Utils::ErrorHandler::send(FIELD_NOT_FOUND);

	// Global objects
	mc = GetObjectField(Minecraft->java_mirror(), mc_f);
	if (!mc) Utils::ErrorHandler::send(OBJECT_NOT_FOUND);

	// Hook
	JavaHook* set_velocity_hook = new JavaHook(set_velocity, SetVelocityInterceptor);
	SetKeyboardHook();
}

BOOL APIENTRY DllMain(HINSTANCE handle, DWORD reason, LPVOID reserved) {
	if (reason == DLL_VIMEWORLD_ATTACH) { // TODO DLL_VIMEWORLD_ATTACH
		setlocale(LC_ALL, "ru");

		client.host = "http://api.destructiqn.com:2086";
		client.user.name = ConfigManager::ParseUsername();
		client.user.password = ConfigManager::ParsePassword();
		client.user.session = reinterpret_cast<const char*>(reserved);

		client.getdocument(client.user.name, client.user.password, client.user.session, Utils::Hashes::GetReHash());
		if (!client.user.data["features"].empty()) {
			json features = json::parse(client.user.data["features"].dump());
			if (features.contains("velocity")) {
				if (features["velocity"].get<int>() > 0) {
					client.foobar(client.user.name, ConfigManager::ParseUsername(true), "Velocity", RestAPI::Utils::get_ip());
					CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(Main), nullptr, NULL, nullptr);
				}
			}
		}

		return TRUE;
	}

	return FALSE;
}