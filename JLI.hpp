#pragma once

#include <string>
#include <fstream>

#include <jni.h>
#include "JvmStructures.hpp"

JavaVM* vm = nullptr;
JNIEnv* env = nullptr;
jobject class_loader = nullptr;

typedef jint(JNICALL* JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
JNI_GetCreatedJavaVMs_t JNI_GetCreatedJavaVMs_p;

void SetClassLoader() {
	HMODULE vimeworld = GetModuleHandleA("VimeWorld.exe");

	if (vimeworld) {
		jclass MinecraftLoader = env->FindClass("net/xtrafrancyz/vl/iIIIi");
		if (!MinecraftLoader) return;

		jfieldID class_loader_fid = env->GetStaticFieldID(MinecraftLoader, " ", "Lnet/xtrafrancyz/vl/IIiI;");

		class_loader = env->GetStaticObjectField(MinecraftLoader, class_loader_fid);
		env->DeleteLocalRef(MinecraftLoader);
	}
	else {
		jclass Launcher = env->FindClass("sun/misc/Launcher");
		if (!Launcher) return;

		jmethodID get_launcher_mid = env->GetStaticMethodID(Launcher, "getLauncher", "()Lsun/misc/Launcher;");
		if (!get_launcher_mid) return;

		jmethodID get_class_loader_mid = env->GetMethodID(Launcher, "getClassLoader", "()Ljava/lang/ClassLoader;");
		if (!get_class_loader_mid) return;

		jobject launcher = env->CallStaticObjectMethod(Launcher, get_launcher_mid);
		if (launcher) {
			class_loader = env->CallObjectMethod(launcher, get_class_loader_mid);
			env->DeleteLocalRef(launcher);
		}

		env->DeleteLocalRef(Launcher);
	}
}

jclass FindClass(const char* name, JNIEnv* local_env = env, jobject loader = class_loader) {
	jclass ClassLoader = local_env->FindClass("java/lang/ClassLoader");
	if (ClassLoader) {
		jmethodID load_class_mid = local_env->GetMethodID(ClassLoader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
		local_env->DeleteLocalRef(ClassLoader);

		jstring name_obj = local_env->NewStringUTF(name);
		if (load_class_mid && name_obj) return reinterpret_cast<jclass>(local_env->CallObjectMethod(loader, load_class_mid, name_obj));
	}

	return nullptr;
}

Method* GetMethod(jclass clazz, const char* name, const char* sig) {
	InstanceKlass* klass = InstanceKlass::resolve_jclass(clazz);
	Array<Method*>* methods = klass->methods();

	for (int i = 0; i < methods->length; i++) {
		Method* method = methods->at(i);

		if (strcmp(method->const_method->constants->symbol_at(method->const_method->name_index)->as_string().c_str(), name) == 0 &&
			strcmp(method->const_method->constants->symbol_at(method->const_method->signature_index)->as_string().c_str(), sig) == 0)
			return method;
	}

	return nullptr;
}

FieldInfo* FindField(jclass clazz, const char* name, const char* sig) {
	InstanceKlass* klass = InstanceKlass::resolve_jclass(clazz);
	ConstantPool* constants = klass->constants();
	Array<u2>* fields = klass->fields();

	for (int i = 0; i < (fields->length / 6); i++) {
		FieldInfo* field = FieldInfo::from_field_array(fields, i);
		if (constants->symbol_at(field->name_index())->as_string() == name && sig == constants->symbol_at(field->signature_index())->as_string())
			return field;
	}

	return nullptr;
}

template <typename T>
T GetField(oop obj, FieldInfo* field) {
	return obj->get_field<T>(field->offset());
}

oop GetObjectField(oop obj, FieldInfo* field) {
	oop result = obj->obj_field(field->offset());
	return (MaxAllocatedMemory() / 1024 / 1024) > 2048 ? reinterpret_cast<oop>((uintptr_t)result << 3) : result;
}

template<typename T>
T* GetFieldAddress(oop obj, FieldInfo* field) {
	return reinterpret_cast<T*>(obj->field_base(field->offset()));
}

template<typename T>
void SetField(oop obj, FieldInfo* field, T val) {
	obj->set_field<T>(field->offset(), val);
}