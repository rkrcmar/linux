#ifndef ARCH_X86_KVM_VMX_H
#define ARCH_X86_KVM_VMX_H

#include <linux/kernel.h>
#include <asm/vmx.h>

struct vmcs_config {
	int size;
	int order;
	u32 basic_cap;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
};

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

#endif
