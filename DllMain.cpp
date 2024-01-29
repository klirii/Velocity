#define _CRT_SECURE_NO_WARNINGS

#include <random>

#include "JavaHook.hpp"
#include "JLI.hpp"

#define DEBUG(format, ...) printf("[!] " format "\n", __VA_ARGS__);
#define M_PI 3.14159265358979323846

#pragma warning(disable:6031)

void InitializeGlobals() {
	jvm = GetModuleHandleA("jvm.dll");
	if (jvm) JNI_GetCreatedJavaVMs_p = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(GetProcAddress(jvm, "IIIIlllllIIl"));
	JNI_GetCreatedJavaVMs_p(&vm, 1, nullptr);

	Offsets::Initialize();
	JavaHook::active_hooks = std::vector<JavaHook*>();
}

jdouble horizontal_multiplier = 0;
jdouble vertical_multiplier = 0;

int horizontal_chance_min = 100;
int horizontal_chance_max = 100;

int vertical_chance_min = 100;
int vertical_chance_max = 100;

bool chance = false;
bool only_forward = false;
bool only_moving = false;

FieldInfo* rotation_yaw_f = nullptr;
FieldInfo* move_forward_f = nullptr;
FieldInfo* player_f = nullptr;

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
	oop instance = hook->GetArgument<oop>(0);
	if (instance->instanceof()->name()->as_string() == "bew") {
		if (chance) {
			horizontal_multiplier = static_cast<jdouble>(GenerateRandomInRange(horizontal_chance_min, horizontal_chance_max)) / 100.0;
			vertical_multiplier = static_cast<jdouble>(GenerateRandomInRange(vertical_chance_min, vertical_chance_max)) / 100.0;
		}

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

	hook->original_code();
}

void Main() {
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	InitializeGlobals();

	vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
	SetClassLoader();

	jclass Entity = FindClass("pk");
	rotation_yaw_f = FindField(Entity, "y", "F");

	Method* set_velocity = GetMethod(Entity, "i", "(DDD)V");
	JavaHook* set_velocity_hook = new JavaHook(set_velocity, SetVelocityInterceptor);
	DEBUG("penis!");

	jclass EntityLivingBase = FindClass("pr");
	move_forward_f = FindField(EntityLivingBase, "ba", "F");

	jclass Minecraft = FindClass("ave");
	FieldInfo* mc_f = FindField(Minecraft, "S", "Lave;");
	player_f = FindField(Minecraft, "h", "Lbew;");
	mc = GetObjectField(oopDesc::resolve_jclass(Minecraft), mc_f);
	
	env->DeleteLocalRef(EntityLivingBase);
	env->DeleteLocalRef(Minecraft);
	env->DeleteLocalRef(Entity);
	vm->DetachCurrentThread();
}

BOOL APIENTRY DllMain(HINSTANCE handle, DWORD reason, LPVOID reserved) {
	if (reason == DLL_PROCESS_ATTACH) {
		CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(Main), nullptr, NULL, nullptr);
		return TRUE;
	}

	return FALSE;
}