#include "AOBScanner.hpp"
#include "Utils.hpp"

#include <Psapi.h>

extern HANDLE current_process;

extern HMODULE    jvm;
extern MODULEINFO jvm_info;

BYTE  k_name_offset              = NULL;
DWORD k_next_link_offset         = NULL;
DWORD k_class_loader_data_offset = NULL;
BYTE k_java_mirror_offset       = NULL;

void* ik_vftable_address  = nullptr;
DWORD ik_methods_offset   = NULL;
DWORD ik_constants_offset = NULL;
DWORD ik_fields_offset    = NULL;

BYTE cld_klasses_offset = NULL;

BYTE m_constmethod_offset = NULL;
BYTE m_i2i_entry_offset   = NULL;
BYTE m_code_offset        = NULL;
BYTE m_flags_offset       = NULL;

DWORD nm_verified_entry_point_offset = NULL;

BYTE cm_constants_offset       = NULL;
BYTE cm_name_index_offset      = NULL;
BYTE cm_signature_index_offset = NULL;

BYTE cp_sizeof = NULL;

void* collected_heap                 = nullptr;
BYTE  collected_heap_capacity_offset = NULL;

#define K_NAME_PATTERN "44 89 71 ? 4C 89 71"
#define K_NEXT_LINK_PATTERN "4C 89 B1 ? ? ? ? 48 C7"
#define K_CLASS_LOADER_DATA_PATTERN "44 89 B3 ? ? ? ? 4C 89 B3 ? ? ? ? 4C 89 B3 ? ? ? ? 66 44"
#define K_JAVA_MIRROR_PATTERN "48 8B 49 ? 48 89 6C 24 ? 48 89"

#define IK_VFTABLE_PATTERN "48 8D 05 ? ? ? ? 45 33 F6"
#define IK_METHODS_PATTERN "4C 8B A2 ? ? ? ? 49 63"
#define IK_CONSTANTS_PATTERN "48 89 82 ? ? ? ? 48 8B 71"
#define IK_FIELDS_PATTERN "48 89 B3 ? ? ? ? 66 89 AB"

#define CLD_KLASSES_PATTERN "4C 89 76 ? 4C 89 76 ? 4C 89 76 ? 44 88"

#define M_CONSTMETHOD_PATTERN "48 8B 51 ? 48 8B 4A ? 0F B7"
#define M_I2I_ENTRY_PATTERN "C7 47 ? ? ? ? ? 48 89 5F ? 48 89 5F"
#define M_CODE_PATTERN "89 9C 24 ? ? ? ? 48 89 5F"
#define M_FLAGS_PATTERN "80 67 ? ? 33 DB"

#define NM_VERIFIED_ENTRY_POINT_PATTERN "48 03 C7 48 89 87"

#define CM_FIELDS_PATTERN "48 8B 51 ? 48 8B 4A ? 0F B7 42"

#define COLLECTED_HEAP_PATTERN "4B 8D 04 09 48 8B E9 48 8B 0D"
#define COLLECTED_HEAP_CAPACITY_PATTERN "FF 50 ? 33 D2 48 8B DD"

#define FIND_AOB(pattern, matches_data_type, reg_attrs, from, to)	\
	std::vector<matches_data_type> matches;							\
	AOBScanner::Scan(												\
		current_process,											\
		pattern,													\
		matches,													\
		reg_attrs,													\
		from,														\
		to															\
	)																\

#define FIND_AOB_IN_MODULE(pattern, matches_data_type, reg_attrs, module_info)	\
	FIND_AOB(																	\
		pattern,																\
		matches_data_type,														\
		reg_attrs,																\
		(BYTE*)module_info.lpBaseOfDll,											\
		(BYTE*)module_info.lpBaseOfDll + module_info.SizeOfImage				\
	)																			\

#define FIND_STRUCT_OFFSET(pattern, result_var, offset_data_type, offset_from_pattern) {							\
	FIND_AOB_IN_MODULE(																								\
		pattern,																									\
		BYTE*,																										\
		AOBScanner::RegionAttributes(PAGE_EXECUTE_READ, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_MAPPED),					\
		jvm_info																									\
	);																												\
	if (matches.size() == 1) result_var = *reinterpret_cast<offset_data_type*>(matches[0] + offset_from_pattern);	\
}																													\

#define FIND_VA_FROM_RVA(pattern, result_var, rva_offset_from_pattern, inst_offset_from_pattern, inst_length) {	\
	FIND_AOB_IN_MODULE(																							\
		pattern,																								\
		BYTE*,																									\
		AOBScanner::RegionAttributes(PAGE_EXECUTE_READ, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_MAPPED),				\
		jvm_info																								\
	);																											\
																												\
	if (matches.size() == 1) {																					\
		signed int rva = *reinterpret_cast<signed int*>(matches[0] + rva_offset_from_pattern);					\
		result_var = (matches[0] + inst_offset_from_pattern + inst_length + rva);								\
	}																											\
}																												\

void FindKlassOffsets() {
	FIND_STRUCT_OFFSET(K_NAME_PATTERN, k_name_offset, BYTE, 7);
	FIND_STRUCT_OFFSET(K_NEXT_LINK_PATTERN, k_next_link_offset, DWORD, 3);
	FIND_STRUCT_OFFSET(K_CLASS_LOADER_DATA_PATTERN, k_class_loader_data_offset, DWORD, 17);
	FIND_STRUCT_OFFSET(K_JAVA_MIRROR_PATTERN, k_java_mirror_offset, BYTE, 3);
}

void FindInstanceKlassOffsets() {
	FIND_VA_FROM_RVA(IK_VFTABLE_PATTERN, ik_vftable_address, 3, 0, 7);
	FIND_STRUCT_OFFSET(IK_METHODS_PATTERN, ik_methods_offset, DWORD, 3);
	FIND_STRUCT_OFFSET(IK_CONSTANTS_PATTERN, ik_constants_offset, DWORD, 3);
	FIND_STRUCT_OFFSET(IK_FIELDS_PATTERN, ik_fields_offset, DWORD, 3);
}

void FindClassLoaderDataOffsets() {
	FIND_STRUCT_OFFSET(CLD_KLASSES_PATTERN, cld_klasses_offset, BYTE, 3);
}

void FindMethodOffsets() {
	FIND_STRUCT_OFFSET(M_CONSTMETHOD_PATTERN, m_constmethod_offset, BYTE, 3);
	FIND_STRUCT_OFFSET(M_I2I_ENTRY_PATTERN, m_i2i_entry_offset, BYTE, 10);
	FIND_STRUCT_OFFSET(M_CODE_PATTERN, m_code_offset, BYTE, 10);
	FIND_STRUCT_OFFSET(M_FLAGS_PATTERN, m_flags_offset, BYTE, 2);
}

void FindNmethodOffsets() {
	FIND_STRUCT_OFFSET(NM_VERIFIED_ENTRY_POINT_PATTERN, nm_verified_entry_point_offset, DWORD, 6);
}

void FindConstMethodOffsets() {
	FIND_STRUCT_OFFSET(CM_FIELDS_PATTERN, cm_constants_offset, BYTE, 7);
	FIND_STRUCT_OFFSET(CM_FIELDS_PATTERN, cm_name_index_offset, BYTE, 20);
	FIND_STRUCT_OFFSET(CM_FIELDS_PATTERN, cm_signature_index_offset, BYTE, 11);
}

void FindConstantPoolOffsets() {
	FIND_STRUCT_OFFSET(CM_FIELDS_PATTERN, cp_sizeof, BYTE, 16);
}

void FindCollectedHeapOffsets() {
	FIND_VA_FROM_RVA(COLLECTED_HEAP_PATTERN, collected_heap, 10, 7, 7);
	FIND_STRUCT_OFFSET(COLLECTED_HEAP_CAPACITY_PATTERN, collected_heap_capacity_offset, BYTE, 2);
}

void FindAllOffsets() {
	FindKlassOffsets();
	FindInstanceKlassOffsets();
	FindClassLoaderDataOffsets();
	FindMethodOffsets();
	FindNmethodOffsets();
	FindConstMethodOffsets();
	FindConstantPoolOffsets();
	FindCollectedHeapOffsets();
}

void DisplayOffsets() {
	// Klass offsets
	DEBUG("Klass _name offset: %hhu", k_name_offset);
	DEBUG("Klass _next_link offset: %d", k_next_link_offset);
	DEBUG("Klass _class_loader_data: %d", k_class_loader_data_offset);
	DEBUG("Klass _java_mirror offset: %hhu", k_java_mirror_offset);

	// InstanceKlass offsets
	DEBUG("InstanceKlass vftable address: %p", ik_vftable_address);
	DEBUG("InstanceKlass _methods offset: %d", ik_methods_offset);
	DEBUG("InstanceKlass _constants offset: %d", ik_constants_offset);
	DEBUG("InstanceKlass _fields offset: %d", ik_fields_offset);

	// ClassLoaderData offsets
	DEBUG("ClassLoaderData _klasses offset: %hhu", cld_klasses_offset);

	// Method offsets
	DEBUG("Method _constmethod offset: %hhu", m_constmethod_offset);
	DEBUG("Method _i2i_entry offset: %hhu", m_i2i_entry_offset);
	DEBUG("Method _code offset: %hhu", m_code_offset);
	DEBUG("Method _flags offset: %hhu", m_flags_offset);

	// nmethod offsets
	DEBUG("nmethod _verified_entry_point offset: %d", nm_verified_entry_point_offset);

	// ConstMethod offsets
	DEBUG("ConstMethod _constants offset: %hhu", cm_constants_offset);
	DEBUG("ConstMethod _name_index offset: %hhu", cm_name_index_offset);
	DEBUG("ConstMethod _signature_index offset: %hhu", cm_signature_index_offset);

	// ConstantPool offsets
	DEBUG("ConstantPool sizeof: %hhu", cp_sizeof);

	// CollectedHeap offsets
	DEBUG("Universe::_collected_heap address: %p", collected_heap);
	DEBUG("CollectedHeap capacity offset: %hhu", collected_heap_capacity_offset);
}