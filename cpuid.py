#!/usr/bin/env python2
# encoding=utf8

import mmap
import ctypes
import platform
from ctypes import c_uint32, c_int, c_size_t, c_void_p

# The registers used to pass args in linux amd64: rdi, rsi, rdx, rcx, r8, r9
OPCODE = [
		0x53,                    # push   %rbx
		0x48, 0x89, 0xf0,        # mov    %rsi, %rax
		0x48, 0x89, 0xd1,		 # mov 	  %rdx, %rcx
		0x0f, 0xa2,              # cpuid
		0x89, 0x07,              # mov    %eax,(%rdi)
		0x89, 0x5f, 0x04,        # mov    %ebx,0x4(%rdi)
		0x89, 0x4f, 0x08,        # mov    %ecx,0x8(%rdi)
		0x89, 0x57, 0x0c,        # mov    %edx,0xc(%rdi)
		0x5b,                    # pop    %rbx
		0xc3                     # ret
]

PROT_READ  = 0x1		# /* Page can be read.  */
PROT_WRITE = 0x2		# /* Page can be written.  */
PROT_EXEC  = 0x4		# /* Page can be executed.  */


class CPUID_RETURN_STRUCT(ctypes.Structure):
	# A simple way to build a struct
	# _fields_ = [(r, c_uint32) for r in ("eax", "ebx", "ecx", "edx")]

	# A more intelligible way to build a struct
	_fields_ = [('eax', ctypes.c_uint32),
				('ebx', ctypes.c_uint32),
				('ecx', ctypes.c_uint32),
				('edx', ctypes.c_uint32)]


class CPUID:
	def __del__(self):
		if self.using_valloc:
			# restore mode of the allocated memory and free it
			ctypes.pythonapi.mprotect.restype = c_int
			ctypes.pythonapi.mprotect.argtypes = [c_void_p, c_size_t, c_int]
			ctypes.pythonapi.mprotect(self.code_addr, self.opcode_len, PROT_READ | PROT_WRITE)

			ctypes.pythonapi.free.restype = None
			ctypes.pythonapi.free.argtypes = [c_void_p]
			ctypes.pythonapi.free(self.code_addr)
		else:
			self.mm.close()

	def __init__(self, arch='x86_64'):
		arch = arch.lower()
		if arch in ("amd64", "x86_64"):
			opcode = OPCODE
		else:
			raise RuntimeError("Not supported Architecture: %s" % arch)

		self.opcode_len = len(opcode)

		# convert python list to a ctype array
		opcode = (ctypes.c_ubyte * self.opcode_len)(*opcode)


		## valloc() calls malloc() to allocate aligned memory on the heap,
		## so we have to set the whole memory page as PROT_READ|PROT_WRITE|PROT_EXEC
		#
		## If we set the mode without [PROT_WRITE], then the left part of the whole page(usually 4K) will not be writable,
		## this will result in segment fault when other process allocated with that and tries to write some data there.
		#
		## When we have no choice but to set the memory 'RWX', then we have to remove PROT_EXEC before we free that part.
		## This is ugly, so we will prefer the mmap way to do this job.

		# ------------------------------ Method 1: using valloc ------------------------------------------
		# self.using_valloc = True
		# ctypes.pythonapi.valloc.restype = ctypes.c_void_p
		# ctypes.pythonapi.valloc.argtypes = [ctypes.c_size_t]
		# ctypes.pythonapi.mprotect.restype = c_int
		# ctypes.pythonapi.mprotect.argtypes = [c_void_p, c_size_t, c_int]
		#
		# self.code_addr = ctypes.pythonapi.valloc(self.opcode_len)
		# if not self.code_addr:
		# 	raise MemoryError("Could not allocate memory")
		# mprotect_ret = ctypes.pythonapi.mprotect(self.code_addr, self.opcode_len, PROT_EXEC | PROT_READ | PROT_WRITE)
		# if mprotect_ret != 0:
		# 	raise OSError("mprotect error! Failed to set mode 'WX' on the memory")
		# ctypes.memmove(self.code_addr, opcode, self.opcode_len)
		# ------------------------------------------------------------------------------------------------

		# ------------------------------ Method 2: using mmap --------------------------------------------
		self.using_valloc = False
		self.mm = mmap.mmap(-1, self.opcode_len, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=mmap.PROT_WRITE | mmap.PROT_READ | mmap.PROT_EXEC)
		self.mm.write(opcode)
		self.code_addr = ctypes.addressof(ctypes.c_int.from_buffer(self.mm))
		# ------------------------------------------------------------------------------------------------

		# build a struct to store return value
		self.ret = CPUID_RETURN_STRUCT()

		# build a struct pointer to be passed to CFUNCTYPE as an argument
		self.ret_type = ctypes.POINTER(CPUID_RETURN_STRUCT)
		self.arg_types = (c_uint32, c_uint32)
		self.func = ctypes.CFUNCTYPE(None, self.ret_type, *self.arg_types)(self.code_addr)

	def do_real(self, eax, ecx):
		self.func(self.ret, eax, ecx)
		# return self.ret.eax, self.ret.ebx, self.ret.ecx, self.ret.edx
		return self.ret


def print_reg(eax, ecx, ret):
	print("0x%08x 0x%02x: eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x" % (eax, ecx, ret.eax, ret.ebx, ret.ecx, ret.edx))


def process():
	machine = platform.machine()
	cpuid = CPUID(machine)
	print("CPU:")

	eax = 0
	max_eax = 0
	real_get = cpuid.do_real
	while eax <= max_eax:
		ret = real_get(eax, 0)
		if eax == 0:
			max_eax = ret.eax

		if eax == 2:
			max_ecx = ret.eax & 0xff
			ecx = 0
			while ecx < max_ecx:
				print_reg(eax, ecx, ret)
				ecx += 1
				ret = real_get(eax, ecx=0)

		elif eax == 4:
			ecx = 0
			while (ret.eax & 0x1f) != 0:
				print_reg(eax, ecx, ret)
				ecx += 1
				ret = real_get(eax, ecx)
		elif eax == 7:
			ecx = 0
			max_ecx = 0
			while ecx <= max_ecx:
				print_reg(eax, ecx, ret)
				if ecx == 0:
					max_ecx = ret.eax
				ecx += 1
				ret = real_get(eax, ecx)
		elif eax == 0xb:
			ecx = 0
			while ret.eax != 0 or ret.ebx != 0:
				print_reg(eax, ecx, ret)
				ecx += 1
				ret = real_get(eax, ecx)
		elif eax == 0xd:
			print_reg(eax, 0, ret)
			valid_xcr0 = ret.edx << 32 | ret.eax
			ret = real_get(eax, ecx=1)
			print_reg(eax, 1, ret)
			valid_xss = ret.edx << 32 | ret.ecx
			valid_ecx = valid_xcr0 | valid_xss
			ecx = 2
			while ecx < 63:
				if (valid_ecx & (1 << ecx)) > 0:
					ret = real_get(eax, ecx)
					print_reg(eax, ecx, ret)
				ecx += 1
		elif eax == 0xf:
			mask = ret.edx
			print_reg(eax, 0, ret)
			# As noted in Intel's Manual, if EDX[1] is 1, then it supports L3 Cache Intel RDT Monitoring
			# 0000 0000, 0000 0000, 0000 0000, 0000 0010(b) == 0x2
			if mask & 0x2 == 0x2:
				ecx = 1
				ret = real_get(eax, ecx)
				print_reg(eax, ecx, ret)
		elif eax == 0x12:
			mask = ret.eax
			print_reg(eax, 0, ret)
			ecx = 1
			for ecx in range(1, 33):
				if mask & (1 << (ecx - 1)):
					ret = real_get(eax, ecx)
					print_reg(eax, ecx, ret)
		elif eax == 0x14 or eax == 0x17:
			ecx = 0
			max_ecx = 0
			while True:
				print_reg(eax, ecx, ret)
				if ecx == 0:
					max_ecx = ret.eax
				ecx += 1
				if ecx > max_ecx:
					break
				ret = real_get(eax, ecx)

		else:
			print_reg(eax, 0, ret)
		eax += 1

	eax = 0x80000000
	max_eax = 0x80000000
	while eax <= max_eax:
		ret = real_get(eax, 0)
		if eax == 0x80000000:
			max_eax = ret.eax

		if eax == 0x80000001d:
			ecx = 0
			while (ret.eax & 0x1f) != 0:
				print_reg(eax, ecx, ret)
				ecx += 1
				ret = real_get(eax, ecx)
		else:
			print_reg(eax, 0, ret)
		eax += 1

	eax = 0x80860000
	max_eax = 0x80860000
	while eax <= max_eax:
		ret = real_get(eax, 0)
		if eax == 0x80860000:
			max_eax = ret.eax
		print_reg(eax, 0, ret)
		eax += 1

	eax = 0xc0000000
	max_eax = 0xc0000000
	while eax <= max_eax:
		ret = real_get(eax, 0)
		if eax == 0xc0000000:
			max_eax = ret.eax
		if max_eax > 0xc0001000:
			max = 0xc0000000
		print_reg(eax, 0, ret)

if __name__ == "__main__":
	process()










