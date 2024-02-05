#pragma once

#include <jni.h>
#include <Psapi.h>

#include "AOBScanner.hpp"

#define JVM_ACC_STATIC 0x0008
#define JVM_ACC_NATIVE 0x0100

#define FIELDINFO_TAG_OFFSET 1
#define FIELDINFO_TAG_SIZE	 2
#define FIELDINFO_TAG_MASK	 3

#pragma warning(disable:6387)
#pragma warning(disable:4312)

class Method;
class oopDesc;
class InstanceKlass;

typedef unsigned char u1;
typedef unsigned short u2;
typedef unsigned int u4, narrowKlass;
typedef oopDesc* oop;

typedef size_t(*max_heap_capacity_t)(void*);
max_heap_capacity_t max_heap_capacity;

HMODULE jvm = nullptr;

namespace Offsets {
	DWORD heap_offset = NULL;

	DWORD InstanceKlass_name_offset = NULL;
	DWORD InstanceKlass_methods_offset = NULL;
	DWORD InstanceKlass_fields_offset = NULL;
	DWORD InstanceKlass_constants_offset = NULL;

	DWORD Method_access_flags_offset = NULL;
	DWORD Method_flags_offset = NULL;
	DWORD Method_i2i_entry_offset = NULL;
	DWORD Method_code_offset = NULL;

	DWORD nmethod_verified_entry_point_offset = NULL;

#define HEAP_PATTERN "48 8B 0D ? ? ? ? 48 3B C2"

#define INSTANCEKLASS_NAME_PATTERN "48 8B 89 ? ? ? ? 4C 8B E8 E8"
#define INSTANCEKLASS_METHODS_PATTERN "48 8B AB ? ? ? ? 48 85 ED ? ? ? ? ? ? 33 FF"
#define INSTANCEKLASS_FIELDS_PATTERN "49 8B 9C 24 ? ? ? ? 48 8D ? ? 48 89"
#define INSTANCEKLASS_CONSTANTS_OFFSET "48 8B CB 48 89 ? ? E8 ? ? ? ? 49 8B 94 24"

#define METHOD_ACCESS_FLAGS_PATTERN "48 8B 1C CB 48 8B CF E8 ? ? ? ? 8B 45"
#define METHOD_I2I_ENTRY_PATTERN "48 83 79 ? ? 4D 8B E0 48 8B F2"
#define METHOD_CODE_PATTERN "48 8B 07 48 89 A8"

#define NMETHOD_VERIFIED_ENTRY_POINT_PATTERN "48 03 C7 48 89 87 ? ? ? ? 48 89 B7"

#define INITIALIZE_OFFSET(pattern, result, offset_type, pattern_offset) {												\
		std::vector<BYTE*> findings;																					\
		AOBScanner::Scan(																								\
			process,																									\
			pattern,																									\
			findings,																									\
			AOBScanner::RegionAttributes(PAGE_EXECUTE_READ | PAGE_GUARD, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_MAPPED),	\
			reinterpret_cast<BYTE*>(mod_info.lpBaseOfDll),																\
			reinterpret_cast<BYTE*>(mod_info.lpBaseOfDll) + mod_info.SizeOfImage										\
		);																												\
		if (findings.size() == 1) result = *reinterpret_cast<offset_type*>(findings[0] + pattern_offset);				\
}																														\

	void Initialize() {
		HANDLE process = GetCurrentProcess();
		MODULEINFO mod_info;
		GetModuleInformation(process, jvm, &mod_info, sizeof(MODULEINFO));
		
		{
			std::vector<BYTE*> findings;
			AOBScanner::Scan(
				process,
				HEAP_PATTERN,
				findings,
				AOBScanner::RegionAttributes(PAGE_EXECUTE_READ | PAGE_GUARD, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_MAPPED),
				reinterpret_cast<BYTE*>(mod_info.lpBaseOfDll),
				reinterpret_cast<BYTE*>(mod_info.lpBaseOfDll) + mod_info.SizeOfImage
			);

			if (findings.size() == 1) {
				signed int heap_rva = *reinterpret_cast<signed int*>(findings[0] + 3);
				heap_offset = static_cast<DWORD>((findings[0] + 7 + heap_rva) - (BYTE*)mod_info.lpBaseOfDll);
			}
		}

		INITIALIZE_OFFSET(INSTANCEKLASS_NAME_PATTERN, InstanceKlass_name_offset, DWORD, 3);
		INITIALIZE_OFFSET(INSTANCEKLASS_METHODS_PATTERN, InstanceKlass_methods_offset, DWORD, 3);
		INITIALIZE_OFFSET(INSTANCEKLASS_FIELDS_PATTERN, InstanceKlass_fields_offset, DWORD, 4);
		INITIALIZE_OFFSET(INSTANCEKLASS_CONSTANTS_OFFSET, InstanceKlass_constants_offset, DWORD, 16);

		INITIALIZE_OFFSET(METHOD_ACCESS_FLAGS_PATTERN, Method_access_flags_offset, u1, 14);
		Method_flags_offset = Method_access_flags_offset + 11;
		INITIALIZE_OFFSET(METHOD_I2I_ENTRY_PATTERN, Method_i2i_entry_offset, u2, 3);
		INITIALIZE_OFFSET(METHOD_CODE_PATTERN, Method_code_offset, DWORD, 6);

		INITIALIZE_OFFSET(NMETHOD_VERIFIED_ENTRY_POINT_PATTERN, nmethod_verified_entry_point_offset, DWORD, 6);
	}
}

void* Heap() {
	return *reinterpret_cast<void**>((BYTE*)jvm + Offsets::heap_offset);
}

size_t MaxAllocatedMemory() {
	void* heap = Heap();
	uintptr_t heap_vftable = *reinterpret_cast<uintptr_t*>(heap);

	if (!max_heap_capacity) max_heap_capacity = *reinterpret_cast<max_heap_capacity_t*>(heap_vftable + 0x68);
	return max_heap_capacity(heap);
}

class Symbol {
public:
	unsigned short length;
	short ref_count;

	int identity_hash;
	char body[1];

	std::string as_string() {
		if (!length) return "";
;		return std::string(body, length);
	}
};

template<typename T>
class Array {
public:
	int length;
	T data[1];

	T at(int i) const {return data[i];}
	T* adr_at(int i) {return &data[i];}
};

class CodeBlob {
public:
	void** vtable;
	const char* name;
	int size;
	int header_size;
	int relocation_size;
	int content_offset;
	int code_offset;
	int frame_complete_offset;

	int data_offset;
	int frame_size;
	void* oop_maps;
	void* strings;
};

class nmethod : public CodeBlob {
public:
	Method* method;
	int entry_bci;
	jmethodID jmethod_id;

	nmethod* osr_link;

	union {
		nmethod* unloading_next;
		nmethod* scavenge_root_link;
	};

	nmethod* oops_do_mark_link;

	void* compiler;

	void* entry_point;
	void* osr_entry_point;

	inline void* verified_entry_point() {
		return *reinterpret_cast<void**>((BYTE*)this + Offsets::nmethod_verified_entry_point_offset);
	}
};

class AccessFlags {
public:
	jint flags;

	bool is_static() { return (flags & JVM_ACC_STATIC) != 0; }
	bool is_native() { return (flags & JVM_ACC_NATIVE) != 0; }
};

class ConstantPool {
public:
	void* vtable;
	void* tags;
	void* cache;
	void* pool_holder;
	void* operands;

	jobject resolved_references;
	void* reference_map;

	int flags;
	int length;

	union {
		int resolved_reference_length;
		int version;
	} saved;

	void* lock;
	uintptr_t unknown;

	Symbol* symbol_at(int index) {
		return *reinterpret_cast<Symbol**>(reinterpret_cast<uintptr_t>(this) + sizeof(ConstantPool) + (index * 8));
	}
};

class ConstMethod {
public:
	uint64_t fingerprint;
	ConstantPool* constants;
	void* stackmap_data;

	int const_method_size;
	u2 flags;
	u1 result_type;

	u2 code_size;
	u2 name_index;
	u2 signature_index;
	u2 method_idnum;

	u2 max_stack;
	u2 max_locals;
	u2 size_of_parameters;
	u2 orig_method_idnum;
};

class Method {
public:
	void** vtable;
	ConstMethod* const_method;
	void* method_data;
	void* method_counters;
	int vtable_index;

	u2 method_size;
	u1 intrinsic_id;
	u1 jfr_towrite				: 1,   // Flags
		caller_sensitive		: 1,
		force_inline			: 1,
		hidden					: 1,
		running_emcp			: 1,
		dont_inline				: 1,
		has_injected_profile	: 1,
								: 2;

	void* adapter;
	void* from_compiled_entry;
	void* from_interpreted_entry;

	inline static Method* resolve_jmethod_id(jmethodID mid) {
		return *reinterpret_cast<Method**>(mid);
	}

	inline AccessFlags* access_flags() {
		return reinterpret_cast<AccessFlags*>((BYTE*)this + Offsets::Method_access_flags_offset);
	}

	inline u1* flags() {
		return reinterpret_cast<u1*>((BYTE*)this + Offsets::Method_flags_offset);
	}

	bool is_static() { return access_flags()->is_static(); }
	bool is_native() { return access_flags()->is_native(); }

	inline void* i2i_entry() {
		return *reinterpret_cast<void**>((BYTE*)this + Offsets::Method_i2i_entry_offset);
	}

	inline nmethod* code() {
		return *reinterpret_cast<nmethod**>((BYTE*)this + Offsets::Method_code_offset);
	}
};

class oopDesc {
public:
	void* _mark;
	union _metadata {
		InstanceKlass* _klass;
		narrowKlass _compressed_klass;
	} _metadata;

	inline void* field_base(int offset) const { return (void*)&((BYTE*)this)[offset]; }

	inline oop obj_field(int offset) {
		return reinterpret_cast<oop>(*reinterpret_cast<uint32_t*>(field_base(offset)));
	}

	template<typename T>
	T get_field(int offset) {
		return *reinterpret_cast<T*>(field_base(offset));
	}

	template<typename T>
	void set_field(int offset, T val) {
		*reinterpret_cast<T*>(field_base(offset)) = val;
	}

	InstanceKlass* klass() {
		return reinterpret_cast<InstanceKlass*>((uintptr_t)this->_metadata._compressed_klass << (int)3);
	}

	inline static oop resolve_jclass(jclass clazz) {
		return *reinterpret_cast<oop*>(clazz);
	}

	inline InstanceKlass* instanceof() {
		return reinterpret_cast<InstanceKlass*>((uintptr_t) * reinterpret_cast<DWORD*>((BYTE*)this + 8) << 3);
	}
};

class InstanceKlass {
public:
	inline static InstanceKlass* resolve_jclass(jclass clazz) {
		return *reinterpret_cast<InstanceKlass**>((uintptr_t)oopDesc::resolve_jclass(clazz) + 0x48);
	}

	inline Array<Method*>* methods() {
		return *reinterpret_cast<Array<Method*>**>((BYTE*)this + Offsets::InstanceKlass_methods_offset);
	}

	inline Array<u2>* fields() {
		return *reinterpret_cast<Array<u2>**>((BYTE*)this + Offsets::InstanceKlass_fields_offset);
	}

	inline ConstantPool* constants() {
		return *reinterpret_cast<ConstantPool**>((BYTE*)this + Offsets::InstanceKlass_constants_offset);
	}

	inline Symbol* name() {
		return *reinterpret_cast<Symbol**>((BYTE*)this + Offsets::InstanceKlass_name_offset);
	}
};

class FieldInfo {
private:
	inline int build_int_from_shorts(u2 low, u2 high) {
		return ((int)((unsigned int)high << 16) | (unsigned int)low);
	}

public:
	enum FieldOffset {
		access_flags_offset = 0,
		name_index_offset = 1,
		signature_index_offset = 2,
		initval_index_offset = 3,
		low_packed_offset = 4,
		high_packed_offset = 5,
		field_slots = 6
	};

	u2 _shorts[field_slots];

	u2 name_index() const { return _shorts[name_index_offset]; }
	u2 signature_index() const { return _shorts[signature_index_offset]; }
	u2 initval_index() const { return _shorts[initval_index_offset]; }

	static FieldInfo* from_field_array(Array<u2>* fields, int index) {
		return reinterpret_cast<FieldInfo*>(fields->adr_at(index * field_slots));
	}

	u4 offset() {
		u2 lo = _shorts[low_packed_offset];
		if ((lo & FIELDINFO_TAG_MASK) == FIELDINFO_TAG_OFFSET)
			return build_int_from_shorts(_shorts[low_packed_offset], _shorts[high_packed_offset]) >> FIELDINFO_TAG_SIZE;

		return 0;
	}
};