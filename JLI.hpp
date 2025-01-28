#include "JavaHook.hpp"

extern ClassLoaderData* class_loader;

ClassLoaderData* FindClassLoader() {
	FIND_AOB(BytesToHexStr((BYTE*)&ik_vftable_address, 8).c_str(), InstanceKlass*, nullptr, nullptr);

	for (int i = 0; i < matches.size(); i++) {
		if (matches[i] == (InstanceKlass*)&ik_vftable_address) continue;
		if (!matches[i]->name()) continue;
		if (matches[i]->name()->as_string().empty()) continue;

		if (strcmp(matches[i]->name()->as_string().c_str(), "net/xtrafrancyz/covered/TexteriaOptions") == 0)
			return matches[i]->class_loader_data();
	}

	return nullptr;
}

InstanceKlass* FindClass(const char* name, ClassLoaderData* loader = class_loader) {
	for (InstanceKlass* klass = loader->klasses(); klass != nullptr; klass = klass->next_link())
		if (strcmp(klass->name()->as_string().c_str(), name) == 0)
			return klass;

	return nullptr;
}

Method* FindMethod(InstanceKlass* klass, const char* name, const char* signature) {
	Array<Method*>* methods = klass->methods();

	for (int i = 0; i < methods->_length; i++) {
		Method* method = methods->at(i);
		ConstantPool* constants = method->constmethod()->constants();

		if (strcmp(constants->symbol_at(method->constmethod()->name_index())->as_string().c_str(), name) == 0 &&
			strcmp(constants->symbol_at(method->constmethod()->signature_index())->as_string().c_str(), signature) == 0)
			return method;
	}

	return nullptr;
}

FieldInfo* FindField(InstanceKlass* klass, const char* name, const char* signature) {
	for (int i = 0; i < (klass->fields()->_length / 6); i++) {
		FieldInfo* field = FieldInfo::from_field_array(klass->fields(), i);

		if (strcmp(klass->constants()->symbol_at(field->name_index())->as_string().c_str(), name) == 0 &&
			strcmp(klass->constants()->symbol_at(field->signature_index())->as_string().c_str(), signature) == 0)
			return field;
	}

	return nullptr;
}

oop GetObjectField(oop obj, FieldInfo* field) {
	oop result = obj->obj_field(field->offset());
	return (Universe::heap()->capacity() / 1024 / 1024) > 2048 ? reinterpret_cast<oop>((uintptr_t)result << 3) : result;
}

template <typename T>
T GetField(oop obj, FieldInfo* field) {
	return obj->get_field<T>(field->offset());
}

template<typename T>
void SetField(oop obj, FieldInfo* field, T value) {
	obj->set_field<T>(field->offset(), value);
}

void DisplayFields(InstanceKlass* klass) {
	for (int i = 0; i < (klass->fields()->_length / 6); i++) {
		FieldInfo* field = FieldInfo::from_field_array(klass->fields(), i);

		DEBUG(
			"Class name: %s, field name: %s, field signature: %s",
			klass->name()->as_string().c_str(),
			klass->constants()->symbol_at(field->name_index())->as_string().c_str(),
			klass->constants()->symbol_at(field->signature_index())->as_string().c_str()
		);
	}
}