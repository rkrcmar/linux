#include <linux/mm.h>
#include <linux/tboot.h>
#include <asm/tlbflush.h>
#include "vmx.h"
#include <linux/sv.h>

static void vmx_vmxon(u64 addr)
{
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr) : "memory", "cc");
}

static void msr_or(u64 msr, u64 bits)
{
	u64 old, new;

	rdmsrl(msr, old);

	new = old | bits;
	if (new != old)
		wrmsrl(msr, new);
}

static struct vmcs *vmx_alloc_vmcs(struct vmcs_config *vmcs_conf)
{
	struct vmcs *vmcs;
	struct page *vmcs_pages;

	vmcs_pages = alloc_pages(GFP_KERNEL, vmcs_conf->order);
	if (!vmcs_pages)
		return NULL;

	vmcs = page_address(vmcs_pages);
	memset(vmcs, 0, vmcs_conf->size);

	vmcs->revision_id = vmcs_conf->revision_id;

	return vmcs;
}

// TODO: rename vmcs_config to vmx_config and its fields to reflect real names
static int vmx_hardware_enable(struct vmcs_config *vmcs_conf)
{
	struct vmcs *vmx_area;

	vmx_area = vmx_alloc_vmcs(vmcs_conf);
	if (!vmx_area)
		return -ENOMEM;

	msr_or(MSR_IA32_FEATURE_CONTROL,
			FEATURE_CONTROL_LOCKED |
			FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX |
			tboot_enabled() ? FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX : 0);

	cr4_set_bits(X86_CR4_VMXE);

	vmx_vmxon(virt_to_phys(vmx_area));

	printk("SV: vmx area at %#llx\n", virt_to_phys(vmx_area));
	// TODO: remember and free vmx_area

	return 0;
}

static int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static int vmx_setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	u64 vmx_basic;
	u32 vmx_procbased_ctls, vmx_procbased_ctls2, vmx_exit_ctls,
	    vmx_pinbased_ctls, vmx_entry_ctls;
	u32 min, opt;
	int r;

	if ((r = rdmsrl_safe(MSR_IA32_VMX_BASIC, &vmx_basic)))
		return r;

	min = 0;
	opt = 0;
	if ((r = adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&vmx_pinbased_ctls)))
		return r;

	min = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
//	      CPU_BASED_USE_MSR_BITMAPS;
	opt = 0;
	if ((r = adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&vmx_procbased_ctls)))
		return r;

	min = SECONDARY_EXEC_ENABLE_EPT |
	      SECONDARY_EXEC_UNRESTRICTED_GUEST;
	opt = 0;
	if ((r = adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS2,
				&vmx_procbased_ctls2)))
		return r;

	min = VM_EXIT_HOST_ADDR_SPACE_SIZE;
	opt = 0;
	if ((r = adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&vmx_exit_ctls)))
		return r;

	min = 0;
	opt = 0;
	if ((r = adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&vmx_entry_ctls)))
		return r;

	vmcs_conf->revision_id = vmx_basic & VMX_BASIC_REVISION_MASK;
	vmcs_conf->size = (vmx_basic & VMX_BASIC_VMCS_SIZE_MASK)
	                            >> VMX_BASIC_VMCS_SIZE_SHIFT;
	vmcs_conf->order = get_order(vmcs_conf->size);
	vmcs_conf->basic_cap = vmx_basic >> 32;
	vmcs_conf->pin_based_exec_ctrl = vmx_pinbased_ctls;
	vmcs_conf->cpu_based_exec_ctrl = vmx_procbased_ctls;
	vmcs_conf->cpu_based_2nd_exec_ctrl = vmx_procbased_ctls2;
	vmcs_conf->vmexit_ctrl         = vmx_entry_ctls;
	vmcs_conf->vmentry_ctrl        = vmx_exit_ctls;

	return 0;
}

static int vmx_enter_root_mode(void)
{
	struct vmcs_config vmcs_conf = {};
	int r;

	if ((r = vmx_setup_vmcs_config(&vmcs_conf)))
		return r;

	if ((r = vmx_hardware_enable(&vmcs_conf)))
		return r;

	return 0;
}

int virtualize_self(void) {
	int r;

	if ((r = vmx_enter_root_mode())) {
		printk("SV: failed to enter VMX root mode (%d)\n", r);
		return r;
	}

	return 0;
}
