---
title: binprotect
date: 2026-04-27 00:00:00 +0000
categories: [low level]
tags: [windows, obfuscator, pe, bin2bin]
---

# 1. Introduction

This obfuscator is bin2bin, which means it takes an already compiled executable binary and reproduces it with the obfuscation passes applied. This can be used to protect an application without having access to the original source code. Only x64 PE (portable executable) files are supported as of now, but there are plans to add support for other binary formats (e.g. ELF) in the future.

Currently, all of the well known bin2bin obfuscators insert a section to the end of the binary to place the obfuscated code or data inside. This is so that the original layout of the binary is still preserved by not having to change the contents of the pre-existing sections. This is much easier to manage as it keeps most of the RVAs (relative addresses) valid.

This project takes a unique approach to bin2bin, where any obfuscated code or data is inserted within the original sections of the binary. This requires tracking every single RVA in the application. The benefits of this approach are:

- Less suspicious to malware analysis as there are no additional executable sections added to the binary. Note: this was tested purely for educational and research purposes.  
- Reduced size of the output executable binary. This is because the original unobfuscated code can be erased from the binary as the sections are able to be resized.  
- Harder for analysis to be done as a reverse engineer will not be able to separate obfuscated and unobfuscated code just by the sections they are in, each routine would have to be checked to see if it is obfuscated.

This document will describe both the rewriting of the executable binary as well as the obfuscation techniques implemented. The following obfuscation techniques have been implemented:

- Virtual machine.  
- Opaque predicates.  
- Control flow flattening.  
- Linear substitution.  
- Mixed boolean arithmetic.

Furthermore, this project also has exceptions support (C++ exceptions and SEH) and is able to obfuscate functions that have exception handling.

To assist with disassembly and discovery of code in the binary, symbol files (both PDB and MAP) are accepted optionally. Providing symbol files is not required but assists with disassembly in complex binaries. Some features such as exceptions support and control flow flattening require a symbol file to be provided.

# 2. Binary rewriter

A binary rewriter takes an executable binary and changes the code or data inside it to produce an output binary with the changes applied.

## 2.1. Relative address tracking

As the obfuscated code is inserted directly into the original sections of the binary, the relative addresses in the program must be tracked so that all references to them can be adjusted. This is so that the references still point to the same location after the code and data has been inserted. Otherwise data or code would be accessed at the wrong location, thus changing the behaviour of the output binary as well as causing severe instability.

Whenever any reference to a relative address is found (e.g. instruction containing rip relative operands or PE data directories), it is added to a tracking list to be updated at the end of the rewriting. The RVA where the reference occurs is tracked (to know where to update the reference) as well as the RVA which is being referenced (to know what RVA to update the reference with).

Whenever the disassembler finds a rip relative instruction, it will add it to a list of references to be updated at the end of the obfuscation. This ensures that all of those instructions are still pointing to the location that they originally had. Other relative instruction(s) cases such as jump tables are also added as references to be updated.

All of the tracked RVAs need to be adjusted whenever any bytes are inserted or removed from the binary. For example, here is the byte insertion handler:

```cpp  
void binwrite::binary_t::insert(const rva_t rva, const std::span<const std::uint8_t> data, const bool inclusive)  
{  
	buffer_.insert_range(buffer_.begin() + rva.value(), data);

	update_rvas(rva, static_cast<rva_t::size_type>(data.size()), inclusive);  
}  
```

`update_rvas` is where every tracked RVA is updated to reflect the change that happened in the binary. Here is a diagram of this process:

![](images/binprotect/figure-1.png)

Figure 1. Relative address tracking.

The data inserted (blue) shifts the current data (grey). The instruction's referenced RVA (orange) updates to point to the same memory, accounting for the inserted data (blue).

## 2.2. Disassembly

All of the potential code entries (exports, entry point, relocations pointing to code section, etc) are added to a disassembly queue. If a symbol file is present, all functions described by the symbol file are also added to the disassembly queue. Each entry in the queue is treated as an individual basic block.

A basic block is a group of instructions with no branches; this means it gets terminated at control flow instructions (e.g. jump, ret, int). Basic blocks do not terminate at calls as they are expected to return in most cases. Some functions do not return (e.g. _CxxThrowException) and will be referred to as 'noreturn' calls from now on.

When a basic block from the disassembly queue is being processed, each instruction is disassembled starting from the top until one of the following happens:

- Another already analysed basic block is reached, causing an overlap. See “Basic block splitting”.  
- Terminating instruction is found (jump, return, int).  
- The instruction disassembly has failed.  
- Code padding has been found.

Below is a diagram of the disassembly and entry of the disassembly queue (code padding check omitted in diagram). This is repeated until the disassembly queue is empty.

![](images/binprotect/figure-2.png)

Figure 2. Disassembly processing.

### 2.2.1 Basic block splitting

If two basic blocks overlap, then one of them must be split. This stops two blocks describing the same instructions. For example:

```nasm  
wcslen proc  
    or      rax, 0FFFFFFFFFFFFFFFFh  
loc_140001078:  
    inc     rax  
    cmp     word ptr [rcx+rax*2], 0  
    jnz     short loc_140001078  
    retn  
wcslen endp  
```

This is an implementation of `wcslen`, which gets the length of a wide string. When the first instruction 'or rax, FFFFFFFFFFFFFFFF' is disassembled as the start of a basic block, it will continue disassembling until the 'retn'.

The 'jnz loc_140001078' jumps back up to form a loop. This will be added as a reference, and the target of the jnz will be added to the disassembly queue as well as the fallthrough branch (the next instruction). The instruction jumps in the **middle** of the already analysed block, so it cannot just form a new block and disassemble again down to the 'retn' as it would have a duplicate representation.

The 'jnz' (conditional jump) would also take the fallthrough branch to create a new basic block too. Now there would be 4 basic blocks that look like this:

Block A:  
```nasm  
    or      rax, 0FFFFFFFFFFFFFFFFh  
loc_140001078:  
    inc     rax  
    cmp     word ptr [rcx+rax*2], 0  
    jnz     short loc_140001078  
```

Block B:

```nasm  
loc_140001078:  
    inc     rax  
    cmp     word ptr [rcx+rax*2], 0  
    jnz     short loc_140001078  
```

Block C:

```nasm  
    retn  
```

Block D:

```nasm  
    retn  
```

This is a misrepresentation of the basic blocks, as it duplicates the same instructions over 4 blocks. This can be fixed by splitting any basic blocks that overlap with the current disassembly. There will not be any duplicated instructions anymore because instead of creating a duplicated representation of the instructions at every overlap, the existing instructions would be transferred to the new basic block. The correct representation using splitting is as follows:

Block A:  
```nasm  
    or      rax, 0FFFFFFFFFFFFFFFFh  
```

Block B:

```nasm  
    inc     rax  
    cmp     word ptr [rcx+rax*2], 0  
    jnz     short loc_140001078  
```

Block C:

```nasm  
    retn  
```

### 2.2.2. Indirect control flow

#### 2.2.2.1. Jump tables

Jump tables are used to store the addresses of the handlers for switch statements. Instead of having a lot of if statements/conditional jumps for every case in a switch statement, a table of the addresses of case statement handlers are held. Here's an example (LLVM/CLANG binary):

```cpp  
std::int32_t sub_140004080(const std::int32_t a1)  
{  
  std::int32_t result;

  switch ( a1 )  
  {  
    case 0:  
      result = 9;  
      break;  
    case 1:  
      result = 4;  
      break;  
    case 2:  
      result = 3;  
      break;  
    case 3:  
      result = 1;  
      break;  
    default:  
      result = 0;  
      break;  
  }

  return result;  
}  
```

This switch statement compiles to the following assembly:

```nasm  
; ecx = a1  
cmp     ecx, 3 ; check if above bounds, must be default case  
ja      short def_140004097 ; goto default if a1 above 3  
mov     ecx, ecx  
mov     eax, ecx  
lea     rcx, jpt_140004097  
movsxd  rax, ds:(jpt_140004097 - 140004100h)[rcx+rax*4] ; select correct index of jump table for a1  
add     rax, rcx  
jmp     rax ; goto index specified - the case handler

jpt_140004097:  
dd offset loc_140004099 - 140004100h ; address of handler for first case  
dd offset loc_1400040D5 - 140004100h ; address of handler for second case  
dd offset loc_1400040BD - 140004100h ; address of handler for third case  
dd offset loc_1400040C9 - 140004100h ; address of handler for fourth case  
```

The 'a1' value is compared with the max value of the cases, and if it is above then it'll go directly to the default handler. If a1 is within the case range, then it accesses its entry in the jump table and jumps to the calculated handler address.

The jump table entries as well as the references to the jump table are tracked so that they are kept intact.

##### 2.2.2.1.1. Bounded jump tables

If a jump table does not describe all ranges of values a switch statement can use, then it will use a bounded table to check the limits. This is to redirect the switch to the default statement if it is outside of the bounds. To parse the number of case statements, the comparison instruction is checked to find the number of entries. For example, the instruction 'cmp ecx, 3' shows that the amount of entries in the jump table is 3.

##### 2.2.2.1.2. Unbounded jump tables

If a jump table fills all possible values the case statements can be (e.g. from UINT8 min value to UINT8 max value for the UINT8 type), then it will use an unbounded table with no limit checks. This is because the compiler knows that the jump tables cover all possible values. There is no comparison instruction to hint the number of jump table entries, so the entries must be brute forced. The base of the table is incrementally checked for valid RVAs in a code section, and each valid entry is tracked. This is not as safe as it could parse other data/instructions as jump table entries, which is why the bounded jump tables check is used where possible.

##### 2.2.2.1.3. Different types of jump tables

The binary rewriter supports jump tables on MSVC (including multi-level tables), LLVM/CLANG, and GCC built binaries.

MSVC jump tables have 2 forms, normal and multi-level. The normal jump tables for MSVC are an array of RVAs. Each RVA points to the case statement handler.

MSVC's multi-level tables are used for switch statements with a vast amount of case statements which share handlers. The multi-level version has 2 tables, 1 for the array of handler RVAs and 1 to match the case values with the indexes in the first table. This prevents the repetition of the RVAs in the first table, as each case value only needs to describe the 1 byte index instead of a 4-byte RVA. Here is an example of a multi-level jump table:

```nasm  
lea     rdx, cs:140000000h  
movsxd  rax, edi ; load value  
movzx   eax, ds:(byte_1400023D8 - 140000000h)[rdx+rax] ; get handler index by value  
mov     ecx, ds:(jpt_14000209D - 140000000h)[rdx+rax*4] ; get RVA of handler by handler index  
add     rcx, rdx  
jmp     rcx

jpt_14000209D dd offset loc_14000209F - 140000000h  
dd offset loc_1400020AB - 140000000h  
dd offset loc_1400020B7 - 140000000h  
dd offset loc_1400020CF - 140000000h  
dd offset loc_1400020E7 - 140000000h  
dd offset loc_1400020F3 - 140000000h  
dd offset loc_1400020FF - 140000000h  
dd offset loc_14000210B - 140000000h  
dd offset loc_140002117 - 140000000h  
dd offset loc_140002123 - 140000000h  
dd offset loc_1400020C3 - 140000000h  
dd offset loc_14000213B - 140000000h  
dd offset loc_140002147 - 140000000h  
dd offset loc_140002153 - 140000000h  
dd offset loc_14000216B - 140000000h  
dd offset loc_140002177 - 140000000h  
dd offset loc_140002183 - 140000000h  
dd offset loc_14000219B - 140000000h  
dd offset loc_1400021A7 - 140000000h  
dd offset loc_1400021B3 - 140000000h  
dd offset loc_1400021BF - 140000000h  
dd offset loc_1400021CB - 140000000h  
dd offset loc_1400021D7 - 140000000h  
dd offset loc_1400021E3 - 140000000h  
dd offset loc_1400021EF - 140000000h  
dd offset loc_1400021FB - 140000000h  
dd offset loc_140002207 - 140000000h  
dd offset loc_140002213 - 140000000h  
dd offset loc_14000221F - 140000000h  
dd offset loc_14000222B - 140000000h  
dd offset loc_140002237 - 140000000h  
dd offset loc_140002243 - 140000000h  
dd offset loc_14000224F - 140000000h  
dd offset loc_14000225B - 140000000h  
dd offset loc_140002267 - 140000000h  
dd offset loc_140002273 - 140000000h  
dd offset loc_14000227F - 140000000h  
dd offset loc_14000228B - 140000000h  
dd offset loc_140002294 - 140000000h  
; ... more handler addresses

byte_1400023D8:  
db 0, 2Bh, 1, 2, 2Bh, 3, 2Bh, 4, 2Bh, 5, 6, 7, 8, 9, 0Ah, 0Bh, 0Ch, 0Dh  
db 2Bh, 0Eh, 0Fh, 10h, 2Bh, 11h, 12h, 13h, 14h, 15h, 2Bh, 16h, 2Bh, 17h  
db 18h, 19h, 1Ah, 1Bh, 1Ch, 2Bh, 1Dh, 1Eh, 1Fh, 20h, 21h, 22h, 2Bh, 23h  
db 24h, 25h, 26h, 2Bh, 2Bh, 2Bh, 2Bh, 2Bh, 2Bh, 2Bh, 2Bh, 2Bh, 2Bh, 2Bh  
; ... more indexes to handler table  
```

LLVM uses a table containing offsets relative to the base of the table. By adding the address of the base of the table with the offset described by the entry the handler address can be calculated.

GCC's jump table is an array of DIR64 relocations. Each relocation points to a case statement's address. Relocations are already tracked so those jump table entries are already fixed up. At runtime, those relocation entries will be offset by the base address so each entry can be dereferenced for the address of the case statement.

#### 2.2.2.2. Edge cases

There are some other forms of indirect control flow that have to be supported. For example, on CLANG binaries using FuncInfo3 C++ exceptions, the continuation address is loaded into the register rax and then returned to the caller. The caller will jump to the continuation address.

```nasm  
lea rax, [rip+X]  
retn  
```

Even if the address the lea points to is in a code section, there is no guarantee it is actually code. Jump tables and strings can be placed in the code sections of a binary for cache locality. The correct code paths must be discovered and disassembled to be able to track the RVA references within it (as well as being able to obfuscate it) so it is crucial that these cases can be identified. These are 'risky' references.

To fix jump tables being added to the disassembly queue incorrectly, the disassembler checks if it is a jump table first before adding those risky references to the queue.

To fix strings being lea'd and added to the disassembly queue incorrectly, the disassembler tries disassembling it as a basic block with extra sanity checks in place (e.g. must have a terminator instruction if it is one of these risky references). If any of these sanity checks fails on a risky reference block, the whole block is ignored and assumed to be data.

If a symbol file is provided, then no data symbol will not be added as a risky reference.

### 2.2.3. Functions

Some obfuscation passes require knowing which basic blocks pertain to which functions. For this reason, all basic blocks are assigned to the corresponding functions that own them. Symbol files are parsed to find all function addresses and place them into a list.

For each function, the following steps are carried out:

- Get the entry basic block to the function (the basic block at the function start address).  
- Assign this entry block to the function.  
- Find all exits to the basic block (fallthrough branches, target branches).  
- For every exit basic block, assign it to the function if it is not the entry block of another function (basic block RVA != any function RVA). These last 2 steps are repeated for every discovered basic block.  
- Any jump tables in the discovered blocks are parsed and their target basic blocks are assigned to the function.

### 2.2.4. 'Noreturn' call handling

Noreturn functions do not return. If a noreturn call happens, the basic block will continue to be disassembled as calls do not terminate basic blocks. The binary is not expected to execute past the call, so the compiler has not inserted adequate code which terminates the basic block. The aforementioned disassembly checks will likely catch these cases and terminate the basic block.

```nasm  
sub_140006310 proc  
    sub     rsp, 38h  
    mov     rax, cs:__security_cookie  
    xor     rax, rsp  
    mov     [rsp+38h+var_8], rax  
    mov     [rsp+38h+pExceptionObject], 2Ah  
    lea     rdx, __TI1H  
    lea     rcx, [rsp+38h+pExceptionObject]  
    call    _CxxThrowException  
    db 0CCh  
sub_140006310 endp  
algn_14000633D:  
    align 20h  
```

For example, in this noreturn _CxxThrowException call, the compiler has inserted padding in the form of INT3 instructions, which would be caught both as padding and as a terminating instruction. There are some other cases such as UD2 instructions being inserted after a noreturn call which are also handled.

This is not an infallible way of detecting it, as [the CodeDefender team also discusses](https://codedefender.io/blog/2024/07/02/), but there are countermeasures in place to correct any disassembly that has gone too far. If any jump table entries are found inside a basic block, then the basic block is split so that the jump table is given priority. This would prevent jump table entries being disassembled as instructions after a noreturn call. If the next instructions are valid code, the basic block would end up being split up anyway when the next address's basic block is getting disassembled/processed.

## 2.3. Exceptions support

### 2.3.1. Unwind support

The obfuscator makes use of stack allocations in its obfuscation passes. This allows it to save the value of registers it uses (e.g. push rax) and restore them after the obfuscation pass completes so registers do not get clobbered. A frame pointer is a register that points to a specific location on the stack.

All stack allocations should be described by the unwind codes for a function (if a frame pointer is not present), which allows the OS exception handler to backtrack the stack to the return address and search for the application's exception handler. These stack allocations must be in the prologue (beginning of the function) due to a limit on how far they can be from the start of the function. If stack allocations are made outside of the prologue the unwind codes cannot describe them and the OS would not be able to unwind, breaking exceptions support.

If a frame pointer is used, the OS does not have to be able to backtrack the stack from the rsp register, and can backtrack it from the frame pointer instead. This means the obfuscator can make stack allocations outside of the prologue without having to describe it in unwind codes.

#### 2.3.1.1 Implementation

The rewriter will insert a frame pointer register into every runtime function that does not already have one. This allows the OS to unwind the stack even after the obfuscator has made stack allocations outside of the prologue.

Below is an example of the changes that are made to the prologue and epilogue of the function:

Original function prologue:

```nasm  
DriverEntry proc  
    sub     rsp, 38h  
```

Modified function prologue:

```nasm  
DriverEntry proc  
    push    rbp  
    push    rbp  
    sub     rsp, 38h  
    lea     rbp, [rsp]  
    lea     rbp, [rsp]  
```

Original function epilogue:

```nasm  
    add     rsp, 38h  
    ren  
DriverEntry endp  
```

Modified function epilogue:

```nasm  
    add     rsp, 38h  
    pop     rbp  
    pop     rbp  
    retn
DriverEntry endp  
```

![](images/binprotect/figure-3.png)

Figure 3. Stack layout before frame pointer insertion.

The non volatile register rbp is used as a frame pointer by the rewriter. Non-volatile registers must be preserved, so the value of rbp is pushed in the prologue and described by unwind codes (so OS unwinder can restore the original value of rbp). The register rbp is pushed 2 times to realign the stack to 16 bytes, the second push is purely for realignment purposes.

As the value of rbp is pushed twice in the prologue, it must also be popped at the end of the function to return the stack pointer to its original value. This is so the return address is at [rsp] for the return instruction.

The respective unwind codes are inserted for these push instructions so the OS knows there are more stack allocations in the prologue (to unwind the frame pointer from). That is why there are 2 pops at the epilogue.

To find those exit basic block(s)/epilogue(s), all of the basic blocks in a function are searched for a 'ret' or a jump that goes outside of the current function. Indirect jumps (e.g. jmp rcx) also count as going outside of the current function, except for jump tables. With all of the exit basic blocks grouped together, the 2 pop instructions can be inserted into them to ensure the effects of the pushes at the prologue are reverted when leaving the function.

The 'lea rbp, [rsp]' at the end of the prologue is there to tell the OS a concrete location of the stack which it can then unwind instead of unwinding from rsp. The respective unwind info and codes are inserted for this frame pointer setting instruction.

![](images/binprotect/figure-4.png)

Figure 4. Wrong stack layout after frame pointer insertion.

The other consideration is stack arguments, which are located before the stack pointer. If in a function the stack is accessed after the local allocation (equal or after the return address's slot), those references must be updated. This is because the pushes adjust the stack by 16 bytes, so all referenced data after it also need to be also shifted by 16 bytes. The above diagram shows how the stack references get unaligned and need to be fixed up.

For example 'mov rax, [rsp+0x90]' would get 0x10 (decimal: 16) added to it so that it still accesses the same stack slot once the pushes are executed. The fixed instruction would be: 'mov rax, [rsp+0xA0]'.

If an instruction accesses past the local stack allocation, it will be adjusted by 16 so it will skip over the pushes that are done on the stack. Sometimes the stack pointer is moved into different registers and accessed through a different register, in which case that register is monitored and adjusted in the same way that is done for the stack pointer.

Another case is catch handlers for exceptions, as in rdx they get the address of the EstablisherFrame (equal to the value of our frame pointer register at the time of the exception). The catch handlers will access the exception function's stack through rdx and hence rdx must also be tracked and adjusted.

Below is the diagram of the stack layout after it has been fixed with the stack reference adjustments.

![](images/binprotect/figure-5.png)

Figure 5. Fixed stack layout after frame pointer insertion.

Exceptions support requires a symbol file to be provided to the obfuscator as it requires having as much information on the binary's symbols as possible.

### 2.3.2. Exception info parsing

The rewriter parses the unwind info of a binary to find exception handler information. Any RVAs found are also tracked. The supported exception handler information types are:

- SEH/C_SCOPE_TABLE (C style exceptions).  
- C++ exceptions of FuncInfo3 and FuncInfo4 types.

#### 2.3.2.1. SEH/C_SCOPE_TABLE

The format for this is an array of the following table entries:

```cpp  
struct c_scope_table_entry_t  
{  
	std::uint32_t begin_rva; // where exception-throwing range begins  
	std::uint32_t end_rva; // where exception-throwing range ends  
	std::uint32_t handler_rva; // the handler type/rva (normally 1)  
	std::uint32_t target_rva; // the catch handler rva  
};

struct c_scope_table_t  
{  
	std::uint32_t entry_count;  
	c_scope_table_entry_t table[1];  
};  
```

The begin/end RVAs describe what range of code can throw an exception. The target RVA describes the catch handler which processes the exception when it happens.

#### 2.3.2.2. FuncInfo3 and FuncInfo4

Used for C++ exceptions, the main difference between FH3 and FH4 is that FH4 uses a compressed format to try to save memory. They share the following descriptors:

- Unwind map - list of C++ objects that need to be destroyed as well as the offset of the object from the frame.  
- Try block map - list of catch handlers and the types that each can catch (e.g. std::runtime_error).   
- IP2State map - describes the state of objects depending on what the current instruction pointer is/ the offset in the function.

FH3 specifics:

- The continuation address in the try block map is kept in code and returned by the catch handler in rax (e.g. lea rax, continuation_address).

FH4 specifics:

- Stores map information in a compressed integer format to save space.  
- The try block map contains the continuation address encoded in the FH4 info structure.

Only MSVC and CLANG/LLVM are supported for C++ exceptions. GCC is not supported for C++ exceptions as it uses a different format than FH3/FH4.

### 2.3.3. RTTI and ThrowInfo parsing

Runtime type information (RTTI) and throw info are structures used to introspect C++ types at runtime, including for throwing exceptions. These structures contain many RVAs and hence must be tracked for stability purposes.

#### 2.3.3.1. RTTI

The 'try block' map in the C++ exception descriptors have type information to know if they catch the thrown type. This type information is called RTTI, and also describes other things about the type, such as:

- Virtual function tables.  
- Type name.  
- Inheriting classes.

For classes without virtual functions, all that is generated is a type descriptor:

```cpp  
struct type_descriptor_t  
{  
	std::uint64_t vftable_address; // this is a DIR64 relocation  
	std::uint64_t unk;  
	char name[1];  
};  
```

This is found by scanning data sections for the DIR64 relocation at the member field 'vftable_address', which is checked if it is real virtual function table.

For classes with virtual functions, a complete object locator and class hierarchy descriptor is generated. The class hierarchy descriptor contains an array of base classes.

```cpp  
struct complete_object_locator_t  
{  
	std::uint32_t signature;  
	std::uint32_t offset;  
	std::uint32_t constructor_offset;  
	std::uint32_t type_rva;  
	std::uint32_t hierarchy_rva;  
	std::uint32_t self_rva;  
};

struct hierarchy_descriptor_t  
{  
	std::uint32_t signature;  
	std::uint32_t attributes;  
	std::uint32_t base_class_count;  
	std::uint32_t base_class_list_rva;  
};

struct base_class_array_t  
{  
	std::uint32_t class_rvas[1];  
};

struct base_class_descriptor_t  
{  
	std::uint32_t type_rva;  
	std::uint32_t element_count;  
	std::uint32_t member_displacement;  
	std::uint32_t unk;  
	std::uint32_t unk1;  
	std::uint32_t attributes;  
	std::uint32_t hierarchy_rva;  
};  
```

To find these, data sections are scanned for DIR64 relocations that point to a complete object locator. Checks are done on the target of the DIR64 relocation to ensure it points to a complete object locator (e.g. does self_rva point to the RVA of the base of the class, do the type descriptors and hierarchy descriptors parse properly).

#### 2.3.3.2. ThrowInfo

ThrowInfo is used to describe how to destroy the exception object once it is processed, as well as the thrown type. The inherited classes of the thrown exception type are described in the catchable type array (contains RTTI references) to ensure the exception handler can match it to the catch statements.

The ThrowInfo is scanned in data sections by checking the catchable type array's contents with the previously discovered RTTI information. All the RVAs of the catchable types and the ThrowInfo are added to the tracking list.

```cpp  
struct throw_info_t  
{  
	std::uint32_t attributes;  
	std::uint32_t pmfn_unwind; // address of exception object destructor  
	std::uint32_t forward_compat;  
	std::uint32_t catchable_type_array;  
};

struct catchable_type_array_t  
{  
	std::uint32_t count;  
	std::uint32_t type_rvas[1];  
};

struct catchable_type_t  
{  
	std::uint32_t attributes;  
	std::uint32_t rva_type;  
	std::uint32_t mdisp;  
	std::uint32_t pdisp;  
	std::uint32_t vdisp;  
	std::uint32_t size_of_thrown_object;  
	std::uint32_t optional_copy_constructor_rva;  
};  
```

# 3. Obfuscation

## 3.1. Virtual machine

This technique takes instructions of the x86-64 architecture and translates them into a virtual CPU architecture. This is much harder to analyse as a reverse engineer would first have to understand the virtual CPU architecture before analysing what the original instructions do.

This implementation uses a generic approach to generating virtual machine handlers so that a wide range of instructions can be obfuscated without having to hardcode handlers for each x86-64 instruction.

![](images/binprotect/figure-6a.png)
![](images/binprotect/figure-6b.png)  
![](images/binprotect/figure-6c.png)  
![](images/binprotect/figure-6d.png) 

Figure 6. Virtual machine architecture.

The original sequence of instructions that get virtualised are replaced with a call to the entry block of the virtual machine.

When entering the virtual machine, all general purpose registers (except rsp) are pushed onto the stack. The rflags register is also pushed onto the stack. These stack slots are used as virtual registers, each corresponding to its original register (so the slot for rax would be used in place of rax). The ordering of these virtual registers in the stack is randomised, so each virtual machine handler's register layout changes.

The push instructions to place the general purpose registers onto the virtual stack layout are also randomised, and can be a 'sub rsp, 8; mov [rsp] reg' or a 'push reg'. This is done to make it harder to build signatures for the virtual machine entry.

Hardware registers are the general purpose registers from the x86-64 architecture. Now that the hardware registers have been saved in their virtual CPU state on the stack, they are free to be clobbered. The virtual machine state tracks a list of currently available hardware registers which can be used by the virtual machine stubs. Once the stub completes, those hardware registers are added back to the list so they can be reused.

Now the application has entered the virtual machine and it is time to pass execution onto the handlers for the target instructions. Target instructions are the x86-64 instructions that are being virtualised into this CPU architecture.

First, the operands for the target instruction need to be loaded onto the stack. The operands' values are loaded into a free hardware register. The operands' values are then obfuscated and pushed onto the stack. This is done from the preceding block to the instruction handler (previous handler or the virtual machine entry block if this is the first handler).

The obfuscation applied to the operands' values is the following:

- Random 16-bit number xor operation on the operand value.  
- One complements negation operation on the operand value.

For immediate operands, this obfuscation can be done at obfuscation time as the value is known, so the computation is not done at runtime and hence is harder to reverse.

Hidden operands which require specific registers (e.g. rsi and rdi for 'rep movsb') are loaded into those specific registers instead of a random hardware register.

In the instruction handler block, the operands are popped off the stack and deobfuscated. The reverse operation is executed to get the original values of the operands.

If the original instruction reads from the rflags register, then rflags is loaded from the stack context before executing the instruction.

If the original instruction writes to the rflags register, then rflags is loaded from the stack context before executing the instruction. After the original instruction executes, the updated rflags is written back to the stack context.

This ensures that virtualised instructions have the exact same flag behaviour as the original instructions.

Inside the instruction handler block, the original x86-64 instruction is encoded to use deobfuscated operands. Once the original instruction executes, the result operands are obfuscated and pushed onto the stack.

If this is the last instruction handler, the next basic block will be the virtual machine exit block. If not, the next block shall be from the next handler.

The next basic block pops the obfuscated result operands off of the stack and applies the same deobfuscation process. The result values are written to their original destination. This could be a virtual register on the stack context or a specific location in memory described by the original instruction.

This process repeats until an instruction in the basic block cannot be virtualised (e.g. an instruction which uses the rsp register).

The virtual machine context then needs to be unloaded to transition back to the non-virtualised code. All the virtual registers are popped off the stack into their corresponding general purpose registers. The modified rflags register is also restored by popping it off the stack. Now, the virtual machine exit block returns back to the caller.

### 3.3.1 Unwind support

If a virtualised instruction throws an exception, the OS needs to be able to unwind out of the virtual machine context to be able to find an appropriate exception handler in the callers.

To allow this to happen, unwind info needs to be added to the binary so that the stack layout of the virtual machine function is known to the OS.

A frame pointer is loaded in rbp because the virtual machine handlers make use of stack allocations outside of the prologue. This means rbp is not allowed to be used as an 'available' hardware register by the virtual machine handlers.

All the virtual machine's hardware registers that are used are pushed onto the stack context, so the corresponding unwind codes are inserted for those pushes.

The runtime function for the virtual machine function is then inserted to the exceptions directory. The virtual machine is now unwindable.

## 3.2. Opaque predicate blocks

This technique creates branches to fake basic blocks with incorrect data flow to confuse a reverse engineer.

Opaque predicates are statements that only evaluate to true or false. 

Basic blocks are duplicated and wrapped in an opaque predicate if statement. One of the blocks will have its data flow skewed so it will be similar, but incorrect.

```cpp  
if (opaque_statement_always_true)  
{  
    … original basic block  
}  
else  
{  
    … incorrect but similar basic block  
}  
```

To further mislead a reverse engineer, all the instruction operands are collected and randomised. Each instruction will be recompiled with random operands from the collected list. This ensures the behaviour of the duplicated block is different to the original.

The location of the blocks are also randomly shuffled, so the physical location of them in memory will not give away which one is the correct branch.

The condition required for the branch selection is also chosen randomly. For example in one iteration, the fallthrough branch of the conditional jump will lead to the correct block. In another iteration, the target branch of the conditional jump will lead to the correct block. This makes it harder to find the correct branch.

The opaque predicate expression itself is also very important, as if it is easy to evaluate then it would not be effective. For this reason, [Fermat's Last Theorem](https://en.wikipedia.org/wiki/Fermat's_Last_Theorem) has been chosen as the opaque expression. Fermat's Last Theorem “states that no three positive integers a, b, and c satisfy the equation a^n + b^n = c^n for any integer value of n greater than 2” (where ^ means power). This expression has been proven to be always false given the conditions. The 3 numbers are chosen, a, b, c and they are raised to a randomly chosen power from 3 to 7. The expression is carried out in a newly created basic block and then the conditional branch is taken to the correct block.

If the parameters a, b, c, and n were known, an attacker could solve the expression and find the correct branch. To hinder this, the parameters are chosen from values decided at runtime: the stack pointer (rsp) and the instruction pointer (ASLR will mean the rip will be relocated at runtime). For example:

```cpp  
if ((rsp^n) + (rip^n) != (c^n))  
{  
     … incorrect but similar basic block  
}  
else  
{  
    … original basic block  
}  
```

## 3.3. Control flow flattening

Control flow is the paths of execution a program takes (e.g. 'if statements'). A change in control flow is when one basic block jumps to another. These changes in control flow can be grouped together into a single dispatcher stub and shuffled to make it harder to understand. The dispatcher stub will be responsible for changing control flow to the next basic block instead of it being done directly.

![](images/binprotect/figure-7.png)

Figure 7. Control flow flattening.

All the basic blocks of a function (except the prologue) are grouped together in a list, and all their branches (conditional, unconditional) are collected. Each basic block is given a unique ID/identifier. A dispatcher stub takes all the potential branches and builds a switch statement with all the IDs as cases. The case statements jump to the target basic block. All jumps to the original basic blocks/the original control flow are replaced with a jump to the switch statement with the correct ID (the ID of the target block).

The physical layout of the basic blocks is shuffled so their memory location does not give any hints as to what the original control flow was.

## 3.4. Linear substitution

This technique takes any numbers encoded in an instruction (memory operand displacements, immediate operands) and hides their true value by calculating them at runtime.

At obfuscation time, a random number value is generated of the same bit width as the original number. This is added to the original number and loaded into an unused register as an immediate operand.

At runtime, the random number is subtracted from the register, which results in the original number.

If R is the random number and N is the original number, the expression is effectively ((R+N) - R).

For memory operands to be re-encoded, the register insertion is done to the base operand. If there is already a base operand, its value is added on top.

For **stack** memory operands being substituted, there is a displacement added to the value to account for stack displacement caused by the pushes. The pushes are used for saving the rflags register as well as the unused register.

Here is an example of the substitution of the memory operand in 'mov [rsp+24h], 0':

```nasm  
push    r11  
pushfq ; save flags for now  
mov     r11, rsp  
add     r11, 1D4D9F71h  
sub     r11, 1D4D9F3Dh  
popfq ; restore flags, the original instruction will now execute and populate flags with the correct values  
mov     dword ptr [r11], 0 ; original instruction substituted (r11 == rsp+24h)  
pop     r11  
```

Here is another example of the substitution of the immediate operand in 'add rbx, 8':

```nasm  
push    r10  
pushfq  
mov     r10, 0FFFFFFFFE3F78112h  
sub     r10, 0FFFFFFFFE3F7810Ah  
popfq  
add     rbx, r10  
pop     r10  
```

## 3.5. Mixed boolean arithmetic

This technique takes regular arithmetic expressions (e.g. x+y) and transforms them into more complex expressions which produce the same result. It does this by substituting expressions for equal linear identities.

For example, (x+y) has the equal identity ((x & y) + (x | y)). When the obfuscator processes (x+y), it will substitute it out for one of those identities which are harder to reverse engineer.

There is a list of identities for the following arithmetic instructions: 'add', 'sub', 'and', 'or', 'xor'. This means that for each of these instructions a more complex, random, substitution is chosen to replace it. The identities being chosen randomly from a list ensures each obfuscation output is different.

To make it harder to deobfuscate, this is applied recursively. This ends up with each substituted identity getting re-substituted multiple times, exponentially growing the complexity. Below is an example of the transformation of (x+y) after 2 passes of this technique:

![](images/binprotect/figure-8.png) 

Figure 8. Mixed boolean arithmetic.

An aspect to consider is the flag computation result of the instruction. The original instruction would have had specific flag behaviour applied to the flags register which will not be the same due to the expression being split into different operations/instructions. To solve this, the obfuscator emulates the flag behaviour by inserting a stub which computes and applies the correct flags.

For 'and', 'or', 'xor' the flag behaviour is the same as the 'test' instruction; by inserting a test instruction with the same operands, the flags will be properly emulated for those 3 substituted instructions.

For 'sub', the 'cmp' instruction has the same flag behaviour, and can be inserted with the same operands for flag calculation.

For 'add', the SF, ZF, PF can be calculated by 'test', but the CF, AF, and OF need to be calculated manually. A stub is then inserted which manually calculates the CF, AF, and OF for the add instruction.

These flag emulation stubs hint at what the original instruction was, so it is only done when absolutely necessary. The entire basic block is scanned for instructions that read flags and write flags. The conditions for adding flag emulation are as follows:

- The MBA instruction is the last flag writing instruction before a flag reading instruction.  
- The MBA instruction is the last flag writing instruction in the basic block.

This ensures that whenever the end of a basic block is reached or the flags are read, they are kept up to date by the flag emulation stub. This prevents conditionals (e.g. if statements) from having the wrong branches taken.

# 4. Source code

The source code for this project can be found on [this GitHub repository](https://github.com/noahware/binprotect).

# 5. Building

Below are example commands to build the project using CMake. Begin execution of these commands from the root directory of the project. Replace 'PATH_TO_VCPKG' with the directory path of a vcpkg installation.

```  
mkdir build  
cd build

cmake .. -DCMAKE_TOOLCHAIN_FILE=PATH_TO_VCPKG/scripts/buildsystems/vcpkg.cmake

cmake --build .   
```

On Windows systems with Visual Studio installed, the last command can be skipped as the project can be built through the generated Visual Studio solution files (.sln). The Visual Studio solution files will be in the 'build/' folder.

# 6. Usage

The obfuscator has a command line based config system. The following can be configured through the command line arguments:

- Which obfuscation passes to use.  
- Path for input binary file.  
- Path for input symbol file (optional).  
- Path for output binary file (optional).

Below is an overview of the command line arguments:

Usage: binprotect binary-path symbol-path [--out-binary-path VAR] [--control-flow-flattening VAR] [--virtual-machine VAR] [--opaque-predicates VAR] [--linear-substitution VAR] [--mixed-boolean-arithmetic VAR]

Positional arguments:  
  binary-path                                               file path of input binary [required]  
  symbol-path                                               file path of input binary's symbols [optional]

  --out, --out-path, --out-binary-path                      desired file path of output binary  
  --cff, --control-flow-flattening                          enable control flow flattening pass [default: 1]  
  --vm, --virtual-machine                                   enable virtual machine pass [default: 1]  
  --opa, --opaque, --opaque-predicate, --opaque-predicates  enable opaque predicate pass [default: 1]  
  --lin, --linear-substitution                              enable linear substitution pass [default: 1]  
  --mba, --mixed-boolean-arithmetic                         specify amount of mixed boolean arithmetic passes [default: 2]

# 7. Acronyms

- bin2bin - binary to binary.
- RVA - relative address.  
- MBA - mixed boolean arithmetic.  
- [SEH - structured exception handling](https://learn.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp).
- FH3 - FuncInfo3.
- FH4 - FuncInfo4.
- [MSVC - Microsoft Visual C++](https://en.wikipedia.org/wiki/Microsoft_Visual_C%2B%2B).  
- [LLVM - low level virtual machine](https://en.wikipedia.org/wiki/LLVM).  
- [CLANG - C/C++ language frontend for LLVM](https://clang.llvm.org/).  
- [GCC - GNU compiler collection](https://en.wikipedia.org/wiki/GNU_Compiler_Collection).
- SF - sign flag.  
- ZF - zero flag.  
- PF - parity flag.  
- CF - carry flag.  
- AF - auxiliary carry flag.  
- OF - overflow flag.

# 8. Credits

The following individuals gave invaluable advice during the development of the project:

- Aita.  
- Papstuc.  
- Eriktion.  
- IDontCode.  
- Abdulla.  
- Brit.  
- Phage.
