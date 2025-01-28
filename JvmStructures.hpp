#include "Offsets.hpp"
#include <jni.h>

#define FIELDINFO_TAG_OFFSET 1
#define FIELDINFO_TAG_SIZE	 2
#define FIELDINFO_TAG_MASK	 3

#pragma warning(disable:4312)

class InstanceKlass;
class oopDesc;

typedef unsigned short u2;
typedef unsigned int u4;
typedef oopDesc* oop;

class Symbol {
public:
	unsigned short _length;
	unsigned short _pad_0;
	int _identity_hash;

	char _body[1];

	std::string as_string() {
		return std::string(_body, _length);
	}
};

template<typename T>
class Array {
public:
	int _length;
	T _data[1];

	T at(int index) { return _data[index]; }
	T* adr_at(int index) { return &_data[index]; }
};

class ClassLoaderData {
public:
	InstanceKlass* klasses() {
		return *reinterpret_cast<InstanceKlass**>((BYTE*)this + cld_klasses_offset);
	}
};

class ConstantPool {
public:
	Symbol* symbol_at(int index) {
		return *reinterpret_cast<Symbol**>((BYTE*)this + cp_sizeof + (index * 8));
	}
};

class ConstMethod {
public:
	ConstantPool* constants() {
		return *reinterpret_cast<ConstantPool**>((BYTE*)this + cm_constants_offset);
	}

	u2 name_index() {
		return *reinterpret_cast<u2*>((BYTE*)this + cm_name_index_offset);
	}

	u2 signature_index() {
		return *reinterpret_cast<u2*>((BYTE*)this + cm_signature_index_offset);
	}
};

class nmethod {
public:
	void* verified_entry_point() {
		return *reinterpret_cast<void**>((BYTE*)this + nm_verified_entry_point_offset);
	}
};

class Method {
public:
	ConstMethod* constmethod() {
		return *reinterpret_cast<ConstMethod**>((BYTE*)this + m_constmethod_offset);
	}

	void* i2i_entry() {
		return *reinterpret_cast<void**>((BYTE*)this + m_i2i_entry_offset);
	}

	nmethod* code() {
		return *reinterpret_cast<nmethod**>((BYTE*)this + m_code_offset);
	}

	inline static Method* resolve_jmethod_id(jmethodID mid) {
		return *reinterpret_cast<Method**>(mid);
	}

	BYTE* flags() {
		return (BYTE*)this + m_flags_offset;
	}
};

class oopDesc {
public:
	inline void* field_base(int offset) const { 
		return reinterpret_cast<void*>(&((BYTE*)this)[offset]);
	}

	inline oop obj_field(int offset) {
		return reinterpret_cast<oop>(*reinterpret_cast<uint32_t*>(field_base(offset)));
	}

	template<typename T>
	T get_field(int offset) {
		return *reinterpret_cast<T*>(field_base(offset));
	}

	template<typename T>
	void set_field(int offset, T value) {
		*reinterpret_cast<T*>(field_base(offset)) = value;
	}

	inline InstanceKlass* instanceof() {
		return reinterpret_cast<InstanceKlass*>((uintptr_t) * reinterpret_cast<DWORD*>((BYTE*)this + 8) << 3);
	}
};

class InstanceKlass {
public:
	Symbol* name() {
		return *reinterpret_cast<Symbol**>((BYTE*)this + k_name_offset);
	}

	ClassLoaderData* class_loader_data() {
		return *reinterpret_cast<ClassLoaderData**>((BYTE*)this + k_class_loader_data_offset);
	}

	oop java_mirror() {
		return *reinterpret_cast<oop*>((BYTE*)this + k_java_mirror_offset);
	}

	InstanceKlass* next_link() {
		return *reinterpret_cast<InstanceKlass**>((BYTE*)this + k_next_link_offset);
	}

	Array<Method*>* methods() {
		return *reinterpret_cast<Array<Method*>**>((BYTE*)this + ik_methods_offset);
	}

	Array<u2>* fields() {
		return *reinterpret_cast<Array<u2>**>((BYTE*)this + ik_fields_offset);
	}

	ConstantPool* constants() {
		return *reinterpret_cast<ConstantPool**>((BYTE*)this + ik_constants_offset);
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

class CollectedHeap {
private:
	typedef size_t(*capacity_t)(CollectedHeap* instance);
public:
	BYTE* vftable;

	size_t capacity() {
		return (*reinterpret_cast<capacity_t*>(vftable + collected_heap_capacity_offset))(this);
	}
};

class Universe {
public:
	static CollectedHeap* heap() {
		return *reinterpret_cast<CollectedHeap**>(collected_heap);
	}
};