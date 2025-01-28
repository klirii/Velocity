#pragma once

#include <Windows.h>
#include <thread>
#include <iostream>
#include <vector>
#include <map>
#include <mutex>
#include <TlHelp32.h>

#ifdef ASSERT
#undef NDEBUG
#include <assert.h>
#endif

#include <udis86.h>
#include "JvmStructures.hpp"

#pragma warning(disable:6001)

#define MAX_INSN_LEN 15
#define STACK_SIZE 1048576

// Puts the address
#define MOV_ADDRESS(stream, opcode, address, additional_reg) {												\
	BYTE mov[10] = {additional_reg ? 0x49 : 0x48, opcode, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};	\
	*reinterpret_cast<decltype(address)*>(mov + 2) = address;												\
	stream.Write(mov, 10);																					\
}																											\

// Saves the register to a CONTEXT64 structure
#define SAVE_REGISTER(stream, name, opcode) {									\
	DWORD offset = FIELD_OFFSET(CONTEXT64, name);								\
	BYTE prefix = 0x48;															\
																				\
	if (offset >= FIELD_OFFSET(CONTEXT64, R8))									\
		prefix = 0x4C;															\
																				\
	BYTE save_##name[7] = {prefix, 0x89, opcode, 0x00, 0x00, 0x00, 0x00};		\
	*reinterpret_cast<DWORD*>(save_##name + 3) = offset;						\
	stream.Write(save_##name, 7);												\
}																				\

// Restores the register
#define RESTORE_REGISTER(stream, name, opcode) {								\
	DWORD offset = FIELD_OFFSET(CONTEXT64, name);								\
	BYTE prefix = 0x4C;															\
																				\
	if (offset < FIELD_OFFSET(CONTEXT64, R8))									\
		prefix = 0x48;															\
																				\
	BYTE restore_##name[7] = {prefix, 0x8B, opcode, 0x00, 0x00, 0x00, 0x00};	\
	*reinterpret_cast<DWORD*>(restore_##name + 3) = offset;						\
	stream.Write(restore_##name, 7);											\
}																				\

// Jumps to a 64-bit address
#define JMP64(stream, to) {																					\
	BYTE jmp[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};	\
	*reinterpret_cast<decltype(to)*>(jmp + 6) = to;															\
	stream.Write(jmp, 14);																					\
}																											\

class JavaHook {
public:

	class Utils {
	public:
		inline static bool GetBit(BYTE number, __int8 bit_pos) {
			return (number & (1 << bit_pos)) != 0;
		}

		inline static void SetBit(BYTE& number, __int8 bit_pos, bool value) {
			if (value) number |= (1 << bit_pos);
			else number &= ~(1 << bit_pos);
		}

		inline static void CopyBits(BYTE& dest, const BYTE& src, __int8 start_bit, __int8 size) {
			//Guarantee((start_bit + size) <= 8, "The start bit is too large to copy the size of the bits");

			for (int i = 0; i < size; i++)
				SetBit(dest, start_bit + i, GetBit(src, start_bit + i));
		}

		template<typename to, typename from>
		static to bit_cast(from src) {
			to dst;
			std::memcpy(&dst, &src, sizeof(to));
			return dst;
		}

		static void EnumerateThreads(DWORD(*action)(HANDLE)) {
			DWORD pid = GetCurrentProcessId();
			DWORD tid = GetCurrentThreadId();

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			THREADENTRY32 entry;
			entry.dwSize = sizeof(THREADENTRY32);

			Thread32First(snapshot, &entry);
			do {
				if (entry.th32OwnerProcessID == pid && entry.th32ThreadID != tid) {
					HANDLE thread_h = OpenThread(THREAD_ALL_ACCESS, FALSE, entry.th32ThreadID);
					DWORD res = action(thread_h);
					CloseHandle(thread_h);
				}
			} while (Thread32Next(snapshot, &entry));

			CloseHandle(snapshot);
		}
	};

	class DECLSPEC_ALIGN(16) CONTEXT64 : public CONTEXT {
	public:
		DWORD64 RFlags;
		CONTEXT64(DWORD64 initializer) : CONTEXT{initializer}, RFlags{initializer} {}
	};

	static std::vector<JavaHook*> active_hooks;

	using ORIGINAL_CODE = void(*)();
	ORIGINAL_CODE original_code;

	Method* method;
	CONTEXT64 registers = {NULL};
	bool compiled = false;

	JavaHook(Method* method, void* interceptor) {
		//Guarantee(method && interceptor, "Invalid parameters");

		this->method = method;
#pragma warning(suppress:6011)
		this->signature = SignatureIterator(method->constmethod()->constants()->symbol_at(method->constmethod()->signature_index()));

		active_hooks.push_back(this);
		Hook(interceptor);
	}

	JavaHook(jmethodID method_id, void* interceptor) {
		//Guarantee(method_id && interceptor, "Invalid parameters");

		this->method = Method::resolve_jmethod_id(method_id);
		this->signature = SignatureIterator(method->constmethod()->constants()->symbol_at(method->constmethod()->signature_index()));

		active_hooks.push_back(this);
		Hook(interceptor);
	}

	~JavaHook() {
		update_thread.~thread();

		VirtualFree(gateway, NULL, MEM_RELEASE);
		VirtualFree(stack, NULL, MEM_RELEASE);

		auto iterator = std::find(active_hooks.begin(), active_hooks.end(), this);
		active_hooks.erase(iterator);
		delete this;
	}

	template<typename T>
	T GetArgument(int index) {
		int args_count = signature.GetArgumentsCount();

		//Guarantee(index - 1 < args_count, "Out of bounds");
		//Guarantee(index >= -1, "The argument index cannot be negative");

		int type = index ? signature.GetArgumentType(index - 1) : NULL;
		bool integer = type ? (type != SignatureIterator::FLOAT_T && type != SignatureIterator::DOUBLE_T) : true;

		if (compiled && integer) {
			if (index == -1) {
				//Guarantee(method->is_native(), "You can get JNIEnv* only from the native method!");
				return Utils::bit_cast<T>(registers.Rcx);
			}

			switch (index) {
				case 0: return Utils::bit_cast<T>(registers.Rdx);
				case 1: return Utils::bit_cast<T>(registers.R8);
				case 2: return Utils::bit_cast<T>(registers.R9);
				case 3: return Utils::bit_cast<T>(registers.Rdi);
				case 4: return Utils::bit_cast<T>(registers.Rsi);
				case 5: return Utils::bit_cast<T>(registers.Rcx);
				default: return *reinterpret_cast<T*>(registers.Rsp + 8 + ((index - 6) * 8));
			}
		}
		else if (compiled) {
			int fp_index = 0;

			for (int i = 0; i < (index - 1); i++)
				if (signature.GetArgumentType(i) == SignatureIterator::FLOAT_T || signature.GetArgumentType(i) == SignatureIterator::DOUBLE_T)
					fp_index++;

			switch (fp_index) {
				case 0: return Utils::bit_cast<T>(registers.Xmm0.Low);
				case 1: return Utils::bit_cast<T>(registers.Xmm1.Low);
				case 2: return Utils::bit_cast<T>(registers.Xmm2.Low);
				case 3: return Utils::bit_cast<T>(registers.Xmm3.Low);
				case 4: return Utils::bit_cast<T>(registers.Xmm4.Low);
				case 5: return Utils::bit_cast<T>(registers.Xmm5.Low);
				case 6: return Utils::bit_cast<T>(registers.Xmm6.Low);
				case 7: return Utils::bit_cast<T>(registers.Xmm7.Low);
				default: return *reinterpret_cast<T*>(registers.Rsp + 8 + ((fp_index - 8) * 8));
			}
		}
		else {
			int offset = 0;

			for (int i = args_count - 1; i >= index; i--) {
				if (signature.GetArgumentType(i) == SignatureIterator::DOUBLE_T) offset += 16;
				else offset += 8;
			}

			return *reinterpret_cast<T*>(registers.Rsp + 8 + offset);
		}

		return Utils::bit_cast<T>(0);
	}

	template<typename T>
	void SetArgument(int index, T value) {
		int args_count = signature.GetArgumentsCount();

		//Guarantee(index - 1 < args_count, "Out of bounds");
		//Guarantee(index >= -1, "The argument index cannot be negative");

		int type = index ? signature.GetArgumentType(index - 1) : NULL;
		bool integer = type ? (type != SignatureIterator::FLOAT_T && type != SignatureIterator::DOUBLE_T) : true;

		if (compiled && integer) {
			if (index == -1) {
				//Guarantee(method->is_native(), "You can get JNIEnv* only from the native method!");
				registers.Rcx = Utils::bit_cast<DWORD64>(value);
			}

			switch (index) {
				case 0: registers.Rdx = Utils::bit_cast<DWORD64>(value); break;
				case 1: registers.R8 = Utils::bit_cast<DWORD64>(value); break;
				case 2: registers.R9 = Utils::bit_cast<DWORD64>(value); break;
				case 3: registers.Rdi = Utils::bit_cast<DWORD64>(value); break;
				case 4: registers.Rsi = Utils::bit_cast<DWORD64>(value); break;
				case 5: registers.Rcx = Utils::bit_cast<DWORD64>(value); break;
				default: *reinterpret_cast<T*>(registers.Rsp + 8 + ((index - 6) * 8)) = value; break;
			}
		}
		else if (compiled) {
			int fp_index = 0;

			for (int i = 0; i < (index - 1); i++)
				if (signature.GetArgumentType(i) == SignatureIterator::FLOAT_T || signature.GetArgumentType(i) == SignatureIterator::DOUBLE_T)
					fp_index++;

			switch (fp_index) {
				case 0:	registers.Xmm0.Low = Utils::bit_cast<ULONGLONG>(value); break;
				case 1: registers.Xmm1.Low = Utils::bit_cast<ULONGLONG>(value); break;
				case 2: registers.Xmm2.Low = Utils::bit_cast<ULONGLONG>(value); break;
				case 3: registers.Xmm3.Low = Utils::bit_cast<ULONGLONG>(value); break;
				case 4: registers.Xmm4.Low = Utils::bit_cast<ULONGLONG>(value); break;
				case 5: registers.Xmm5.Low = Utils::bit_cast<ULONGLONG>(value); break;
				case 6: registers.Xmm6.Low = Utils::bit_cast<ULONGLONG>(value); break;
				case 7: registers.Xmm7.Low = Utils::bit_cast<ULONGLONG>(value); break;
				default: *reinterpret_cast<T*>(registers.Rsp + 8 + ((fp_index - 8) * 8)) = value; break;
			}
		}
		else {
			int offset = 0;
			if (!index) offset += 8;

			for (int i = args_count - 1; i >= index; i--) {
				if (signature.GetArgumentType(i) == SignatureIterator::DOUBLE_T) offset += 16;
				else offset += 8;
			}

			*reinterpret_cast<T*>(registers.Rsp + 8 + offset) = value;
		}
	}

	//static void DisableIntegrityChecks() {
	//	DWORD old_protect = NULL;
	//	VirtualProtect((BYTE*)brainstorm + Offsets::integrity_check_offset, 7, PAGE_EXECUTE_READWRITE, &old_protect);
	//	memset((BYTE*)brainstorm + Offsets::integrity_check_offset + 4, 0x90, 3);
	//	VirtualProtect((BYTE*)brainstorm + Offsets::integrity_check_offset, 7, old_protect, &old_protect);
	//}

private:

	class InstructionBufferStream {
	public:
		BYTE* current;
		int size;
		int pos;

		InstructionBufferStream() = default;

		InstructionBufferStream(BYTE* buffer, int size) {
			this->buffer = buffer;
			current = this->buffer;
			this->size = size;
			this->pos = 0;
		}

		void Write(BYTE* instruction, int size) {
			//Guarantee(pos < this->size, "The buffer size is too small to write an instruction into it");
			if (WriteProcessMemory(GetCurrentProcess(), current, instruction, size, nullptr)) {
				current += size;
				pos += size;
			}
		}

	private:
		BYTE* buffer;
	};

	class SignatureIterator {
	public:
		enum BasicType {
			VOID_T,
			BOOLEAN_T,
			BYTE_T,
			CHAR_T,
			SHORT_T,
			INT_T,
			LONG_T,
			FLOAT_T,
			DOUBLE_T,
			OBJECT_T,
			ARRAY_T
		};

		SignatureIterator() = default;

		SignatureIterator(Symbol* signature) {
			//Guarantee(signature->length, "The signature cannot be an empty string");
			this->signature = signature->as_string();
			ParseArgumentsTypes();
		}

		void ParseArgumentsTypes() {
			int index = 1;
			int parameter_index = 0;

			while (signature[index] != ')') {
				switch (signature[index]) {
					case 'V': {
						arguments_types.insert(std::make_pair(parameter_index, VOID_T));
						parameter_index++;
						index++;
						break;
					}
					case 'Z': {
						arguments_types.insert(std::make_pair(parameter_index, BOOLEAN_T));
						parameter_index++;
						index++;
						break;
					}
					case 'B': {
						arguments_types.insert(std::make_pair(parameter_index, BYTE_T));
						parameter_index++;
						index++;
						break;
					}
					case 'C': {
						arguments_types.insert(std::make_pair(parameter_index, CHAR_T));
						parameter_index++;
						index++;
						break;
					}
					case 'S': {
						arguments_types.insert(std::make_pair(parameter_index, SHORT_T));
						parameter_index++;
						index++;
						break;
					}
					case 'I': {
						arguments_types.insert(std::make_pair(parameter_index, INT_T));
						parameter_index++;
						index++;
						break;
					}
					case 'J': {
						arguments_types.insert(std::make_pair(parameter_index, LONG_T));
						parameter_index++;
						index++;
						break;
					}
					case 'F': {
						arguments_types.insert(std::make_pair(parameter_index, FLOAT_T));
						parameter_index++;
						index++;
						break;
					}
					case 'D': {
						arguments_types.insert(std::make_pair(parameter_index, DOUBLE_T));
						parameter_index++;
						index++;
						break;
					}
					case 'L': {
						++index;
						while (signature[index++] != ';');

						arguments_types.insert(std::make_pair(parameter_index, OBJECT_T));
						parameter_index++;
						break;
					}
					case '[': {
						++index;
						while (signature[index] == '[') index++;

						if (signature[index] == 'L') while (signature[index++] != ';');
						else index++;

						arguments_types.insert(std::make_pair(parameter_index, ARRAY_T));
						parameter_index++;
						break;
					}
				}
			}
		}

		int GetArgumentsCount() {
			return static_cast<int>(arguments_types.size());
		}

		int GetArgumentType(int index) {
			//Guarantee(index < GetArgumentsCount(), "Out of bounds");
			return arguments_types[index];
		}

	private:
		std::string signature;
		std::map<int, int> arguments_types;
	};
	
	bool initialized = false;

	SignatureIterator signature;
	std::thread update_thread;

	BYTE* i2i_entry_shell;
	bool i2i_entry_hooked = false;
	std::vector<BYTE> i2i_entry_reserved_instructions;

	int unfixed_length = 0;
	std::vector<BYTE> fixed_reserved;

	LPVOID stack;

	BYTE* gateway;
	InstructionBufferStream gateway_stream;

	inline static bool Guarantee(bool expression, const char* message) {
#ifdef ASSERT
		if (!expression) MessageBoxA(NULL, message, "Assertion failed!", MB_ABORTRETRYIGNORE | MB_ICONSTOP);
#else
		if (!expression) return false;
#endif
		return true;
	}

	static std::vector<BYTE> GetFixedReservedInstructions(void* entry_point, OUT int& unfixed_length) {
		// Set entry point page protection in PAGE_EXECUTE_READWRITE
		DWORD old_protect = NULL;
		VirtualProtect(entry_point, MAX_INSN_LEN * 3, PAGE_EXECUTE_READWRITE, &old_protect);

		// Initialize udis to disassemble the entry point
		ud_t ud;
		ud_init(&ud);
		ud_set_mode(&ud, 64);
		ud_set_input_buffer(&ud, reinterpret_cast<const uint8_t*>(entry_point), MAX_INSN_LEN * 3);

		int bytes_counter = 0;
		std::vector<BYTE> instructions;

		while (ud_disassemble(&ud) && bytes_counter < 14) {
			const unsigned int insn_len = ud_insn_len(&ud);
			const BYTE* insn_bytes		= ud_insn_ptr(&ud);

			const ud_operand* opr_1		= ud_insn_opr(&ud, 0);
			const ud_operand* opr_2		= ud_insn_opr(&ud, 1);

			bytes_counter += insn_len;
			signed int rva = NULL;

			if ((ud.mnemonic >= UD_Ija && ud.mnemonic < UD_Ijmp) || (ud.mnemonic > UD_Ijmp && ud.mnemonic <= UD_Ijz)) {
				if (opr_1->type == UD_OP_JIMM) {
					if (insn_len == 2) rva = (signed int)*reinterpret_cast<const signed __int8*>(insn_bytes + 1);
					else if (insn_len == 6) rva = *reinterpret_cast<const signed int*>(insn_bytes + 2);
				}
			}
			else if (ud.mnemonic == UD_Ijmp || ud.mnemonic == UD_Icall) {
				if (opr_1->type == UD_OP_JIMM) {
					if (insn_len == 5) rva = *reinterpret_cast<const signed int*>(insn_bytes + 1);
					else if (insn_len == 2) rva = (signed int)*reinterpret_cast<const signed __int8*>(insn_bytes + 1);
				}
				else if (opr_1->type == UD_OP_MEM && opr_1->base == UD_R_RIP && insn_len == 6)
					rva = *reinterpret_cast<const signed int*>(insn_bytes + 2);
			}
			else if (ud.mnemonic == UD_Imov && opr_2->type == UD_OP_MEM && opr_2->base == UD_R_RIP && insn_len == 7) {
				rva = *reinterpret_cast<const signed int*>(insn_bytes + 3);
			}

			if (rva) {
				uintptr_t va = reinterpret_cast<uintptr_t>(entry_point) + ud_insn_off(&ud) + insn_len + rva;

				if (opr_1->type == UD_OP_MEM && opr_1->base == UD_R_RIP && insn_len == 6 || ud.mnemonic == UD_Imov) {
					BYTE push_r10[2] = {0x41, 0x52};
					instructions.insert(instructions.end(), push_r10, push_r10 + 2);

					BYTE mov_r10[10] = {0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
					*reinterpret_cast<uintptr_t*>(mov_r10 + 2) = va;
					instructions.insert(instructions.end(), mov_r10, mov_r10 + 10);

					if (ud.mnemonic == UD_Icall || ud.mnemonic == UD_Ijmp) {
						BYTE call_or_jmp[3] = { 0x41, 0xFF, 0x00 };
						call_or_jmp[2] = ud.mnemonic == UD_Icall ? 0x12 : 0x22;
						instructions.insert(instructions.end(), call_or_jmp, call_or_jmp + 3);
					}
					else if (ud.mnemonic == UD_Imov) {
						BYTE mov[3] = { 0x00, 0x8B, 0x02 };
						mov[0] = ud.pfx_rex + 1;
						Utils::CopyBits(mov[2], ud.modrm, 3, 3);
						instructions.insert(instructions.end(), mov, mov + 3);
					}

					BYTE pop_r10[2] = {0x41, 0x5A};
					instructions.insert(instructions.end(), pop_r10, pop_r10 + 2);
					continue;
				}
				else if (ud.mnemonic == UD_Icall) {
					BYTE call64[16] = {0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
					*reinterpret_cast<uintptr_t*>(call64 + 8) = va;
					instructions.insert(instructions.end(), call64, call64 + 16);
					continue;
				}
				else if ((ud.mnemonic >= UD_Ija && ud.mnemonic < UD_Ijmp) || (ud.mnemonic > UD_Ijmp && ud.mnemonic <= UD_Ijz)) {
					BYTE cond_jmp_buf[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
					memcpy(cond_jmp_buf, insn_bytes, insn_len - (opr_1->size / 8));
					instructions.insert(instructions.end(), cond_jmp_buf, cond_jmp_buf + insn_len);
				}

				BYTE jmp64[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				*reinterpret_cast<uintptr_t*>(jmp64 + 6) = va;

				instructions.insert(instructions.end(), jmp64, jmp64 + 14);
				continue;
			}

			instructions.insert(instructions.end(), insn_bytes, insn_bytes + insn_len);
		}

		// Restore the protection of the entry point page
		VirtualProtect(entry_point, MAX_INSN_LEN * 3, old_protect, &old_protect);
		unfixed_length = bytes_counter;
		return instructions;
	}

	static DWORD GetAdditionalStackSpaceSize(void* interceptor) {
		DWORD old_protect = NULL;
		VirtualProtect(interceptor, 64, PAGE_EXECUTE_READWRITE, &old_protect);

		ud_t ud;
		ud_init(&ud);
		ud_set_mode(&ud, 64);
		ud_set_input_buffer(&ud, reinterpret_cast<const uint8_t*>(interceptor), 64);

		DWORD last_mov_rsp_offset = NULL;
		while (ud_disassemble(&ud)) {
			if (ud.mnemonic == UD_Isub || ud.mnemonic == UD_Iret || ud.mnemonic == UD_Iint3) break;

			const ud_operand* opr = ud_insn_opr(&ud, 0);
			if (ud.mnemonic == UD_Imov && opr->type == UD_OP_MEM && opr->size == 64 && opr->base == UD_R_RSP)
				if (opr->lval.udword > last_mov_rsp_offset)
					last_mov_rsp_offset = opr->lval.udword;
		}

		VirtualProtect(interceptor, 64, old_protect, &old_protect);
		return last_mov_rsp_offset;
	}

	static uintptr_t AlignStack(uintptr_t address) {
		address -= address % 8;
		address -= address % 16 == 0 ? 8 : 0;
		return address;
	}

	void InitializeGateway(void* interceptor) {
		// Save the rax register into the registers structure
		MOV_ADDRESS(gateway_stream, 0xA3, &registers.Rax, false);

		// Put the address of the registers structure into the rax register
		MOV_ADDRESS(gateway_stream, 0xB8, &registers, false);

		// Save other registers to the registers structure
		SAVE_REGISTER(gateway_stream, Rcx, 0x88);
		SAVE_REGISTER(gateway_stream, Rdx, 0x90);
		SAVE_REGISTER(gateway_stream, Rbx, 0x98);
		SAVE_REGISTER(gateway_stream, Rsp, 0xA0);
		SAVE_REGISTER(gateway_stream, Rbp, 0xA8);
		SAVE_REGISTER(gateway_stream, Rsi, 0xB0);
		SAVE_REGISTER(gateway_stream, Rdi, 0xB8);
		SAVE_REGISTER(gateway_stream, R8, 0x80);
		SAVE_REGISTER(gateway_stream, R9, 0x88);
		SAVE_REGISTER(gateway_stream, R10, 0x90);
		SAVE_REGISTER(gateway_stream, R11, 0x98);
		SAVE_REGISTER(gateway_stream, R12, 0xA0);
		SAVE_REGISTER(gateway_stream, R13, 0xA8);
		SAVE_REGISTER(gateway_stream, R14, 0xB0);
		SAVE_REGISTER(gateway_stream, R15, 0xB8);

		// Allocate the local stack for the interceptor
		stack = VirtualAlloc(NULL, STACK_SIZE, MEM_COMMIT, PAGE_READWRITE);
		//Guarantee(stack, "Stack allocation for the interceptor has failed");

		// We make the stack aligned on an 8-byte boundary but not aligned on a 16-byte boundary
		uintptr_t stack_base = AlignStack(reinterpret_cast<uintptr_t>(stack) + STACK_SIZE - 40);

		// Put the base of the stack into rbp and rsp
		MOV_ADDRESS(gateway_stream, 0xBD, stack_base, false);
		MOV_ADDRESS(gateway_stream, 0xBC, stack_base, false);

		// Save the flags register on the stack
		BYTE pushfq = 0x9C;
		gateway_stream.Write(&pushfq, 1);

		// Pop the flags register from the stack to the registers structure
		BYTE pop_rflags[6] = { 0x8F, 0x80, 0x00, 0x00, 0x00, 0x00 };
		*reinterpret_cast<DWORD*>(pop_rflags + 2) = FIELD_OFFSET(CONTEXT64, RFlags);
		gateway_stream.Write(pop_rflags, 6);

		// Save the FPU state to the registers structure
		BYTE fxsave[7] = { 0x0F, 0xAE, 0x80, 0x00, 0x00, 0x00, 0x00 };
		*reinterpret_cast<DWORD*>(fxsave + 3) = FIELD_OFFSET(CONTEXT64, FltSave);
		gateway_stream.Write(fxsave, 7);

		// Allocate additional space on the stack for the interceptor before it is called
		BYTE sub_rsp[7] = {0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00};
		DWORD space_size = GetAdditionalStackSpaceSize(interceptor);

		// Aligning the size of the space
		uintptr_t aligned_stack = AlignStack(stack_base - space_size);
		space_size = static_cast<DWORD>(stack_base - aligned_stack);

		*reinterpret_cast<DWORD*>(sub_rsp + 3) = space_size;
		gateway_stream.Write(sub_rsp, 7);

		// Pass a pointer to the JavaHook object as the first argument, before calling the interceptor
		MOV_ADDRESS(gateway_stream, 0xB9, this, false);

		// Call the interceptor and set the return address
		JMP64(gateway_stream, interceptor);
		original_code = reinterpret_cast<ORIGINAL_CODE>(gateway_stream.current);

		// Put the address of the registers structure into the rax register
		MOV_ADDRESS(gateway_stream, 0xB8, &registers, false);

		// Restore FPU state
		BYTE fxrstor[7] = { 0x0F, 0xAE, 0x88, 0x00, 0x00, 0x00, 0x00 };
		*reinterpret_cast<DWORD*>(fxrstor + 3) = FIELD_OFFSET(CONTEXT64, FltSave);
		gateway_stream.Write(fxrstor, 7);

		// Push the flags register from the registers structure onto the stack
		BYTE push_rflags[6] = { 0xFF, 0xB0, 0x00, 0x00, 0x00, 0x00 };
		*reinterpret_cast<DWORD*>(push_rflags + 2) = FIELD_OFFSET(CONTEXT64, RFlags);
		gateway_stream.Write(push_rflags, 6);

		// Restore the flags register
		BYTE popfq = 0x9D;
		gateway_stream.Write(&popfq, 1);

		// Restore other registers
		RESTORE_REGISTER(gateway_stream, R15, 0xB8);
		RESTORE_REGISTER(gateway_stream, R14, 0xB0);
		RESTORE_REGISTER(gateway_stream, R13, 0xA8);
		RESTORE_REGISTER(gateway_stream, R12, 0xA0);
		RESTORE_REGISTER(gateway_stream, R11, 0x98);
		RESTORE_REGISTER(gateway_stream, R10, 0x90);
		RESTORE_REGISTER(gateway_stream, R9, 0x88);
		RESTORE_REGISTER(gateway_stream, R8, 0x80);
		RESTORE_REGISTER(gateway_stream, Rdi, 0xB8);
		RESTORE_REGISTER(gateway_stream, Rsi, 0xB0);
		RESTORE_REGISTER(gateway_stream, Rbp, 0xA8);
		RESTORE_REGISTER(gateway_stream, Rsp, 0xA0);
		RESTORE_REGISTER(gateway_stream, Rbx, 0x98);
		RESTORE_REGISTER(gateway_stream, Rdx, 0x90);
		RESTORE_REGISTER(gateway_stream, Rcx, 0x88);

		// Restore the rax register
		BYTE restore_rax[4] = { 0x48, 0x8B, 0x40, 0x00 };
		*reinterpret_cast<BYTE*>(restore_rax + 3) = FIELD_OFFSET(CONTEXT64, Rax);
		gateway_stream.Write(restore_rax, 4);
	}

	void InitializeI2iEntryShell(InstructionBufferStream& shell) {
		if (active_hooks.size() > 1) Utils::EnumerateThreads(SuspendThread);
		memset(i2i_entry_shell, 0, 4096);

		BYTE pushfq = 0x9C;
		BYTE popfq = 0x9D;

		BYTE push_r10[2] = {0x41, 0x52};
		BYTE pop_r10[2] = {0x41, 0x5A};

		shell.Write(&pushfq, 1);
		shell.Write(push_r10, 2);

		for (int i = 0; i < active_hooks.size(); i++) {
			MOV_ADDRESS(shell, 0xBA, active_hooks[i]->method, true);

			BYTE cmp_method[3] = {0x4C, 0x39, 0xD3};
			shell.Write(cmp_method, 3);

			BYTE jnz[2] = {0x75, 0x11};
			shell.Write(jnz, 2);

			shell.Write(pop_r10, 2);
			shell.Write(&popfq, 1);

			JMP64(shell, active_hooks[i]->gateway);
		}

		shell.Write(pop_r10, 2);
		shell.Write(&popfq, 1);

		if (active_hooks.size() > 1) Utils::EnumerateThreads(ResumeThread);
	}

	void Update() {
		while (!method->i2i_entry()) Sleep(100);
		nmethod* code = reinterpret_cast<nmethod*>(1);

		if (active_hooks.size() > 1) i2i_entry_shell = active_hooks[0]->i2i_entry_shell;
		else i2i_entry_shell = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE));

		InstructionBufferStream shell(i2i_entry_shell, 4096);
		InitializeI2iEntryShell(shell);

		bool i2i_entry_match_hooked = false;
		int	 i2i_entry_match_hook_index = 0;

		BYTE* initialized_gateway = nullptr;
		int initialized_gateway_pos = NULL;

		const BYTE* initialized_shell = shell.current;
		const int initialized_shell_pos = shell.pos;

		while (true) {
			compiled = method->code() ? true : false;

			if (!compiled && method->i2i_entry() && !i2i_entry_hooked || compiled && method->code() != code) {
				if (!compiled) Utils::EnumerateThreads(SuspendThread);

				for (int i = 0; i < active_hooks.size(); i++) {
					if (active_hooks[i] != this && active_hooks[i]->method->i2i_entry() == method->i2i_entry()) {
						if (active_hooks[i]->i2i_entry_hooked) i2i_entry_match_hooked = true;
						else i2i_entry_match_hooked = false;

						i2i_entry_match_hook_index = i;
						break;
					}
				}

				if (!compiled && i2i_entry_match_hooked) {
					fixed_reserved = active_hooks[i2i_entry_match_hook_index]->fixed_reserved;
					unfixed_length = active_hooks[i2i_entry_match_hook_index]->unfixed_length;
				}
				else {
					fixed_reserved = GetFixedReservedInstructions(
						compiled ? method->code()->verified_entry_point() : method->i2i_entry(), unfixed_length
					);
				}

				uintptr_t backward_address = compiled ? (uintptr_t)method->code()->verified_entry_point() + unfixed_length : (uintptr_t)shell.current;

				if (compiled && i2i_entry_hooked) {
					i2i_entry_hooked = false;

					if (!i2i_entry_match_hooked) {
						WriteProcessMemory(
							GetCurrentProcess(),
							method->i2i_entry(),
							i2i_entry_reserved_instructions.data(),
							i2i_entry_reserved_instructions.size(),
							nullptr
						);
						i2i_entry_reserved_instructions.clear();
					}
				}

				// Shell
				if (!compiled) {
					memset(const_cast<BYTE*>(initialized_shell), 0, shell.size - shell.pos);

					shell.Write(fixed_reserved.data(), static_cast<int>(fixed_reserved.size()));
					JMP64(shell, reinterpret_cast<uintptr_t>(method->i2i_entry()) + unfixed_length);
					FlushInstructionCache(GetCurrentProcess(), i2i_entry_shell, shell.size);

					shell.current = const_cast<BYTE*>(initialized_shell);
					shell.pos = initialized_shell_pos;

					if (i2i_entry_match_hooked) {
						i2i_entry_reserved_instructions = active_hooks[i2i_entry_match_hook_index]->i2i_entry_reserved_instructions;
					}
					else {
						i2i_entry_reserved_instructions.insert(
							i2i_entry_reserved_instructions.end(),
							(BYTE*)method->i2i_entry(),
							(BYTE*)method->i2i_entry() + unfixed_length
						);
					}
				}

				// Gateway
				for (int i = 0; i < active_hooks.size(); i++) {
					if (active_hooks[i]->method->i2i_entry() == method->i2i_entry() || compiled) {
						for (int j = 0; j < active_hooks.size() && compiled; j++)
							if (active_hooks[j] == this) i = j;

						initialized_gateway = active_hooks[i]->gateway_stream.current;
						initialized_gateway_pos = active_hooks[i]->gateway_stream.pos;

						memset(initialized_gateway, 0, active_hooks[i]->gateway_stream.size - initialized_gateway_pos);

						if (compiled) gateway_stream.Write(fixed_reserved.data(), static_cast<int>(fixed_reserved.size()));
						JMP64(active_hooks[i]->gateway_stream, backward_address);

						FlushInstructionCache(GetCurrentProcess(), active_hooks[i]->gateway, active_hooks[i]->gateway_stream.size);
						active_hooks[i]->gateway_stream.current = initialized_gateway;
						active_hooks[i]->gateway_stream.pos = initialized_gateway_pos;

						if (compiled) break;
					}
				}

				// Set hook
				if (!i2i_entry_match_hooked || compiled) {
					std::vector<BYTE> jmp_far = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
					jmp_far.insert(
						jmp_far.end(),
						compiled ? reinterpret_cast<BYTE*>(&gateway) : reinterpret_cast<BYTE*>(&i2i_entry_shell),
						compiled ? reinterpret_cast<BYTE*>(&gateway) + 8 : reinterpret_cast<BYTE*>(&i2i_entry_shell + 8)
					);

					if (unfixed_length > 14)
						for (int i = 0; i < unfixed_length - 14; i++)
							jmp_far.push_back(0x90);

					WriteProcessMemory(
						GetCurrentProcess(),
						compiled ? method->code()->verified_entry_point() : method->i2i_entry(),
						jmp_far.data(),
						unfixed_length,
						nullptr
					);
				}

				if (compiled) code = method->code();
				else i2i_entry_hooked = true;

				initialized = true;
				if (!compiled) Utils::EnumerateThreads(ResumeThread);
			}

			Sleep(25);
		}
	}

	void Hook(void* interceptor) {
		// Set the dont_inline method flag to true so that the method cannot be inlined
		Utils::SetBit(*method->flags(), 5, 1);

		// Allocate a gateway to save registers, flags and stack before interceptor call and restore them afterwards
		gateway = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
		//Guarantee(gateway, "The allocation of a gateway has failed");

		// Create a stream buffer to write instructions to the gateway and initialize it
		gateway_stream = InstructionBufferStream(gateway, 4096);
		InitializeGateway(interceptor);

		update_thread = std::thread(&JavaHook::Update, this);
		update_thread.detach();

		while (!initialized) Sleep(25);
	}
};

std::vector<JavaHook*> JavaHook::active_hooks;