#include <linux/mm.h>
#include <linux/tboot.h>
#include <asm/tlbflush.h>
#include "vmx.h"
#include <linux/sv.h>

struct sv_vcpu_vmx {
	u8 fail;
	u64 host_rsp;
	u64 guest_cr2;
	u64 regs[NR_VCPU_REGS];
	struct {
		u64 total;
		u64 cr4;
		u64 cpuid;
		u64 rdmsr;
		u64 vmcall;
	} exits __packed;
};

static void dump_regs(struct sv_vcpu_vmx *vmx)
{
	int reg;
	for (reg = 0; reg < NR_VCPU_REGS - 4; reg += 4) {
		printk("%016llx %016llx %016llx %016llx\n",
				vmx->regs[reg],     vmx->regs[reg + 1],
				vmx->regs[reg + 2], vmx->regs[reg + 3]);
	}
}

#define vmx_bug(vmx) do { dump_regs(vmx); dump_vmcs(); BUG(); } while(0)

// needed for __ex()
__visible bool kvm_rebooting;
asmlinkage __visible void kvm_spurious_fault(void)
{
	BUG();
}

// TODO: unify
static void vmx_vmxon(u64 addr)
{
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr) : "memory", "cc");
}

// TODO: unify
static int vmx_vmcs_load(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
			: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printk(KERN_ERR "SV: vmptrld %p/%llx failed (%u)\n",
		       vmcs, phys_addr, error);
	return error;
}

static int msr_or(u64 msr, u64 bits)
{
	int r;
	u64 old, new;

	if ((r = rdmsrl_safe(msr, &old)))
		return WARN_ON(r);

	new = old | bits;
	if (new != old)
		return WARN_ON(wrmsrl_safe(msr, new));
	return 0;
}

static struct vmcs *vmx_alloc_vmcs(struct vmcs_config *vmcs_conf)
{
	struct vmcs *vmcs;
	struct page *vmcs_pages;

	vmcs_pages = alloc_pages(GFP_KERNEL, vmcs_conf->order);
	if (WARN_ON(!vmcs_pages))
		return NULL;

	vmcs = page_address(vmcs_pages);
	memset(vmcs, 0, vmcs_conf->size);

	vmcs->revision_id = vmcs_conf->revision_id;

	return vmcs;
}

// TODO: rename vmcs_config to vmx_config and its fields to reflect real names
static int vmx_hardware_enable(struct vmcs_config *vmcs_conf)
{
	int r;
	struct vmcs *vmx_area;

	vmx_area = vmx_alloc_vmcs(vmcs_conf);
	if (!vmx_area)
		return -ENOMEM;

	if ((r = msr_or(MSR_IA32_FEATURE_CONTROL,
			FEATURE_CONTROL_LOCKED |
			FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)))
			// XXX: FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX with TPM?
		return r;

	/* do not confuse the guest by writing X86_CR4_VMXE to CR4 shadow */
	__write_cr4(cr4_read_shadow() | X86_CR4_VMXE);

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
	if (WARN_ON(ctl_min & ~ctl))
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

	min = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS
	    | CPU_BASED_USE_MSR_BITMAPS
	    ;
	opt = 0;
	if ((r = adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&vmx_procbased_ctls)))
		return r;

	// XXX: highly experimental without EPT (not supported on all CPUs)
	vmx_procbased_ctls &= ~(CPU_BASED_CR3_LOAD_EXITING |
	                        CPU_BASED_CR3_STORE_EXITING |
	                        CPU_BASED_INVLPG_EXITING);

	min = 0;
//	    | SECONDARY_EXEC_UNRESTRICTED_GUEST
//	    | SECONDARY_EXEC_ENABLE_EPT
	opt = SECONDARY_EXEC_ENABLE_INVPCID  // maybe opt
	    | SECONDARY_EXEC_RDTSCP
	    | SECONDARY_EXEC_XSAVES
	    ;
	if ((r = adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS2,
				&vmx_procbased_ctls2)))
		return r;

	min = VM_EXIT_HOST_ADDR_SPACE_SIZE
//	    | VM_EXIT_LOAD_IA32_EFER | VM_EXIT_SAVE_IA32_EFER;
	    ;

	opt = 0;
	if ((r = adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&vmx_exit_ctls)))
		return r;

	min = VM_ENTRY_IA32E_MODE; // TODO: need to toggle this?
//		VM_ENTRY_LOAD_IA32_EFER;
	opt = 0;
	if ((r = adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&vmx_entry_ctls)))
		return r;

	vmcs_conf->revision_id = vmx_basic & VMX_BASIC_REVISION_MASK;
	vmcs_conf->size = (vmx_basic & VMX_BASIC_VMCS_SIZE_MASK)
	                            >> VMX_BASIC_VMCS_SIZE_SHIFT;
	vmcs_conf->order = get_order(vmcs_conf->size);
	vmcs_conf->basic_cap = vmx_basic >> 32;

	vmcs_conf->pin_based_exec_ctrl     = vmx_pinbased_ctls;
	vmcs_conf->cpu_based_exec_ctrl     = vmx_procbased_ctls;
	vmcs_conf->cpu_based_2nd_exec_ctrl = vmx_procbased_ctls2;
	vmcs_conf->vmexit_ctrl             = vmx_exit_ctls;
	vmcs_conf->vmentry_ctrl            = vmx_entry_ctls;

	return 0;
}

static int vmx_vmcs_setup(struct sv_vcpu_vmx *vmx,
		struct vmcs_config *vmcs_conf)
{
	unsigned long *msr_bitmap;

	/*
	 * 64 bit control fields
	 */
	// IO bitmap A and B -- not needed, because “unconditional I/O exiting”
	//                      and “use I/O bitmaps” VM exec controls are 0
	// VM entry/exit load/store -- not needed, counts are 0.
	// executive VMCS -- not needed outside of dual-monitor SMM
	// TSC offset -- 0
	msr_bitmap = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!msr_bitmap)
		return -ENOMEM;
	memset(msr_bitmap, 0, PAGE_SIZE); /* never exit for gives MSR ranges */
	vmcs_write64(MSR_BITMAP, __pa(msr_bitmap));

	// XXX: not tested
	if (vmcs_conf->cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_XSAVES)
		vmcs_write64(XSS_EXIT_BITMAP, 0); /* never exit on xsaves/xrstors */

	/*
	 * 32 bit control fields
	 */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vmcs_conf->pin_based_exec_ctrl);
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vmcs_conf->cpu_based_exec_ctrl);

	/* never exits on exceptions */
	vmcs_write32(EXCEPTION_BITMAP, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	vmcs_write32(CR3_TARGET_COUNT, 0);

	vmcs_write32(VM_EXIT_CONTROLS, vmcs_conf->vmexit_ctrl);
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);

	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_conf->vmentry_ctrl);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0); // XXX: losing interrupts?
	vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, 0); // XXX: and exceptions?
	vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 0); // XXX: useless?

	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0); /* no interrupt masking */
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);

	vmcs_write32(SECONDARY_VM_EXEC_CONTROL, vmcs_conf->cpu_based_2nd_exec_ctrl);
	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_conf->vmentry_ctrl);

	vmcs_write64(VMCS_LINK_POINTER, -1ull);

	/*
	 * natural-width control fields
	 */
	vmcs_writel(0x6000, 0); // XXX: name CR0 guest/host mask
	/* VMXE was enabled for puposes of our hypervisor, but the guest must
	 * see it as disabled, otherwise it won't run VMX, thinking it is
	 * already being used. */
	vmcs_writel(0x6002, X86_CR4_VMXE); // XXX: name CR4 guest/host mask
	vmcs_writel(CR0_READ_SHADOW, 0);
	vmcs_writel(CR4_READ_SHADOW, 0);  /* X86_CR4_VMXE looks disabled on entry */
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0); // XXX: losing this as well?
	// CR3 target value 0.. -- not needed

	return 0;
}

static int vmx_prepare_vcpu(struct sv_vcpu_vmx *vmx,
		struct vmcs_config *vmcs_conf)
{
	int r;
	struct vmcs *vmcs;

	vmcs = vmx_alloc_vmcs(vmcs_conf);
	if (!vmcs)
		return -ENOMEM;

	if ((r = vmx_vmcs_load(vmcs)))
		return r;

	if ((r = vmx_vmcs_setup(vmx, vmcs_conf)))
		return r;

	return 0;
}

#define asm_read_g(type, code) \
({\
	type val; \
	asm (code " %0" : "=g"(val)); \
	val; \
})

static unsigned long get_desc_base64(struct desc_struct *d)
{
	unsigned long v;

	if (!d)
		return 0;

	v = get_desc_base(d);
	if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
		v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;
	return v;
}

static u32 get_desc_ar(struct desc_struct *d)
{
	if (!d)
		return 0x10000; // maybe 0x1c000

	return d->type | d->s << 4 | d->dpl << 5 | d->p << 7 |
		d->avl << 12 | d->l << 13 | d->d << 14 | d->g << 15;
//	return d->b >> 8 | (d->b >> 20) << 8;
}

static u32 get_desc_limit_safe(struct desc_struct *d)
{
	return d ? get_desc_limit(d) : 0; // maybe 0xffffffff or 0xffff
}

static struct desc_struct * get_segment(struct desc_ptr *gdt, u16 ldtrs, u16 selector)
{
	// XXX: possibly wrong!
	unsigned long table_base = gdt->address;

	if (!(selector & ~3))
		return NULL;

	if (selector & 4) {
		struct desc_struct *ldt = get_segment(gdt, 0, ldtrs);
		if (!ldt)
			return NULL;
		table_base = get_desc_base64(ldt);
	}

	/* Linux "optimizes" selector indices with "& ~7", but better be safe. */
	return (struct desc_struct *)(table_base + (selector >> 3) * 8);
}

static int load_current_state(struct sv_vcpu_vmx *vmx)
{
	u64 msr;
	struct desc_ptr gdt, idt;
	u16 ess, css, sss, dss, fss, gss, trs, ldtrs;
	struct desc_struct *es, *cs, *ss, *ds, *fs, *gs, *tr, *ldtr;

	native_store_gdt(&gdt);
	native_store_idt(&idt);

	ess = asm_read_g(u16, "mov %%es,");
	css = asm_read_g(u16, "mov %%cs,");
	sss = asm_read_g(u16, "mov %%ss,");
	dss = asm_read_g(u16, "mov %%ds,");
	fss = asm_read_g(u16, "mov %%fs,");
	gss = asm_read_g(u16, "mov %%gs,");
	trs = asm_read_g(u16, "str");
	ldtrs = asm_read_g(u16, "sldt");

	es = get_segment(&gdt, ldtrs, ess);
	cs = get_segment(&gdt, ldtrs, css);
	ss = get_segment(&gdt, ldtrs, sss);
	ds = get_segment(&gdt, ldtrs, dss);
	fs = get_segment(&gdt, ldtrs, fss);
	gs = get_segment(&gdt, ldtrs, gss);
	tr = get_segment(&gdt, ldtrs, trs);
	ldtr = get_segment(&gdt, ldtrs, ldtrs);

	/* 16 bit state fields */
	vmcs_write16(GUEST_ES_SELECTOR, ess);
	vmcs_write16(GUEST_CS_SELECTOR, css);
	vmcs_write16(GUEST_SS_SELECTOR, sss);
	vmcs_write16(GUEST_DS_SELECTOR, dss);
	vmcs_write16(GUEST_FS_SELECTOR, fss);
	vmcs_write16(GUEST_GS_SELECTOR, gss);
	vmcs_write16(GUEST_LDTR_SELECTOR, ldtrs);
	vmcs_write16(GUEST_TR_SELECTOR, trs);

	vmcs_write16(HOST_ES_SELECTOR, ess);
	vmcs_write16(HOST_CS_SELECTOR, css);
	vmcs_write16(HOST_SS_SELECTOR, sss);
	vmcs_write16(HOST_DS_SELECTOR, dss);
	vmcs_write16(HOST_FS_SELECTOR, fss);
	vmcs_write16(HOST_GS_SELECTOR, gss);
	vmcs_write16(HOST_TR_SELECTOR, trs);

	/* 64 bit state fields */
	// link pointer -- -1 from before
	rdmsrl_safe(MSR_IA32_DEBUGCTLMSR, &msr);
	vmcs_write64(GUEST_IA32_DEBUGCTL, msr);

	/* 32 bit fields */
	vmcs_write32(GUEST_ES_LIMIT, get_desc_limit_safe(es));
	vmcs_write32(GUEST_CS_LIMIT, get_desc_limit_safe(cs));
	vmcs_write32(GUEST_SS_LIMIT, get_desc_limit_safe(ss));
	vmcs_write32(GUEST_DS_LIMIT, get_desc_limit_safe(ds));
	vmcs_write32(GUEST_FS_LIMIT, get_desc_limit_safe(fs));
	vmcs_write32(GUEST_GS_LIMIT, get_desc_limit_safe(gs));
	vmcs_write32(GUEST_LDTR_LIMIT, get_desc_limit_safe(ldtr));
	vmcs_write32(GUEST_TR_LIMIT, get_desc_limit_safe(tr));
	// TR and LDTR limit
	vmcs_write32(GUEST_GDTR_LIMIT, gdt.size);
	vmcs_write32(GUEST_IDTR_LIMIT, idt.size);
	vmcs_write32(GUEST_ES_AR_BYTES, get_desc_ar(es));
	vmcs_write32(GUEST_CS_AR_BYTES, get_desc_ar(cs));  // XXX: wrong handling of NULL segment
	vmcs_write32(GUEST_SS_AR_BYTES, get_desc_ar(ss));
	vmcs_write32(GUEST_DS_AR_BYTES, get_desc_ar(ds));
	vmcs_write32(GUEST_FS_AR_BYTES, get_desc_ar(fs));
	vmcs_write32(GUEST_GS_AR_BYTES, get_desc_ar(gs));
	vmcs_write32(GUEST_LDTR_AR_BYTES, get_desc_ar(ldtr));
	vmcs_write32(GUEST_TR_AR_BYTES, get_desc_ar(tr));
	// pending debug exceptinos -- loaded from before
	// interruptibility state -- loaded from before
	// activity state -- loaded from before
	rdmsrl_safe(MSR_IA32_SMBASE, &msr);
	vmcs_write32(0x4828, msr); // XXX: name GUEST_SMBASE
	rdmsrl_safe(MSR_IA32_SYSENTER_CS, &msr);
	vmcs_write32(GUEST_SYSENTER_CS, (u32)msr);
	vmcs_write32(HOST_IA32_SYSENTER_CS, (u32)msr);

	/* natural-width state fields */
	vmcs_writel(GUEST_CR0, asm_read_g(long, "mov %%cr0,"));
	vmcs_writel(GUEST_CR3, asm_read_g(long, "mov %%cr3,"));
	vmcs_writel(GUEST_CR4, asm_read_g(long, "mov %%cr4,"));
	vmcs_writel(GUEST_ES_BASE, get_desc_base64(es));
	vmcs_writel(GUEST_CS_BASE, get_desc_base64(cs));
	vmcs_writel(GUEST_SS_BASE, get_desc_base64(ss));
	vmcs_writel(GUEST_DS_BASE, get_desc_base64(ds));
	rdmsrl_safe(MSR_FS_BASE, &msr);
	vmcs_writel(GUEST_FS_BASE, msr);// get_desc_base64(fs));
	rdmsrl_safe(MSR_GS_BASE, &msr);
	vmcs_writel(GUEST_GS_BASE, msr); //get_desc_base64(gs));
	vmcs_writel(GUEST_LDTR_BASE, get_desc_base64(ldtr));
	vmcs_writel(GUEST_TR_BASE, get_desc_base64(tr));
	vmcs_writel(GUEST_GDTR_BASE, gdt.address);
	vmcs_writel(GUEST_IDTR_BASE, idt.address);
	vmcs_writel(GUEST_DR7, asm_read_g(long, "mov %%dr7,"));
	// guest RSP -- loaded later
	// guest RIP -- loaded later
	// guest RFLAGS -- loaded later
	// guest pending debug exceptions -- loaded from before
	vmcs_writel(GUEST_DR7, asm_read_g(long, "mov %%dr7,"));
	rdmsrl_safe(MSR_IA32_SYSENTER_ESP, &msr);
	vmcs_writel(GUEST_SYSENTER_ESP, (long)msr); // XXX: rename to GUEST_IA32_SYSENTER_ESP
	rdmsrl_safe(MSR_IA32_SYSENTER_EIP, &msr);
	vmcs_writel(GUEST_SYSENTER_EIP, (long)msr);

	vmcs_writel(HOST_CR0, asm_read_g(long, "mov %%cr0,"));
	vmcs_writel(HOST_CR3, asm_read_g(long, "mov %%cr3,"));
	vmcs_writel(HOST_CR4, asm_read_g(long, "mov %%cr4,"));
	rdmsrl_safe(MSR_FS_BASE, &msr);
	vmcs_writel(HOST_FS_BASE, msr); //? msr : get_desc_base64(fs));
	rdmsrl_safe(MSR_GS_BASE, &msr);
	vmcs_writel(HOST_GS_BASE, msr); //? msr : get_desc_base64(gs));
	vmcs_writel(HOST_TR_BASE, get_desc_base64(tr));
	vmcs_writel(HOST_GDTR_BASE, gdt.address);
	vmcs_writel(HOST_IDTR_BASE, idt.address);
	rdmsrl_safe(MSR_IA32_SYSENTER_ESP, &msr);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, (long)msr);
	// host RSP -- loaded later
	// host RIP -- loaded later

	/*
	rdmsrl_safe(MSR_EFER, &msr);
	vmcs_write64(GUEST_IA32_EFER, msr);
	vmcs_write64(HOST_IA32_EFER, msr);
	*/

	// C is not a good language for error checking ... better not to make any
	return 0;
}

#define STACK_SIZE 16384
static char hypervisor_stack[STACK_SIZE + 1] __aligned(PAGE_SIZE);

extern const long guest_entry;
extern const long hypervisor_entry;

void vmx_vmresume(struct sv_vcpu_vmx *vmx);

static void vmx_instruction_handled(struct sv_vcpu_vmx *vmx)
{
	u64 guest_rip = vmcs_readl(GUEST_RIP);
	vmcs_writel(GUEST_RIP, guest_rip + vmcs_read32(VM_EXIT_INSTRUCTION_LEN));
}

static int handle_cr_access(struct sv_vcpu_vmx *vmx)
{
	u64 exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	u8 cr = exit_qualification & 15;
	u8 reg = (exit_qualification >> 8) & 15;

	switch ((exit_qualification >> 4) & 3) {
	case 0: /* MOV to CR */
		if (cr == 4) {
			vmx->exits.cr4++;
			vmcs_writel(GUEST_CR4,       vmx->regs[reg] | X86_CR4_VMXE);
			vmcs_writel(CR4_READ_SHADOW, vmx->regs[reg] & X86_CR4_VMXE);
			break;
		}
		/* fallthrough, should not exit */
	case 1: /* MOV from CR */ /* should not exit */
	case 2: /* CLTS */  // XXX: not tested
	case 3: /* LMSW */  // XXX: not tested
		vmx_bug(vmx);
	}

	vmx_instruction_handled(vmx);

	return 0;
}

static int handle_cpuid(struct sv_vcpu_vmx *vmx)
{
	u32 eax, ebx, ecx, edx;

	eax = vmx->regs[VCPU_REGS_RAX];
	ecx = vmx->regs[VCPU_REGS_RCX];

	native_cpuid(&eax, &ebx, &ecx, &edx);

	vmx->regs[VCPU_REGS_RAX] = eax;
	vmx->regs[VCPU_REGS_RBX] = ebx;
	vmx->regs[VCPU_REGS_RCX] = ecx;
	vmx->regs[VCPU_REGS_RDX] = edx;

	vmx->exits.cpuid++;

	vmx_instruction_handled(vmx);
	return 0;
}

static int handle_msr_read(struct sv_vcpu_vmx *vmx)
{
	vmx->exits.rdmsr++;

	if (rdmsr_safe(vmx->regs[VCPU_REGS_RCX],
			&vmx->regs[VCPU_REGS_RAX], &vmx->regs[VCPU_REGS_RDX])) {
		printk("SV: faking MSR 0x%llx\n", vmx->regs[VCPU_REGS_RCX]);
		vmx->regs[VCPU_REGS_RAX] = 0;
		vmx->regs[VCPU_REGS_RDX] = 0;
	}

	vmx_instruction_handled(vmx);
	return 0;
}

static int handle_vmcall(struct sv_vcpu_vmx *vmx)
{
	vmx->exits.vmcall++;

	switch (vmx->regs[VCPU_REGS_RAX]) {
	case 1:
		vmx->regs[VCPU_REGS_RAX] = vmx->exits.total;
		vmx->regs[VCPU_REGS_RBX] = vmx->exits.cr4;
		vmx->regs[VCPU_REGS_RCX] = vmx->exits.cpuid;
		vmx->regs[VCPU_REGS_RDX] = vmx->exits.rdmsr;
		vmx->regs[VCPU_REGS_RSI] = vmx->exits.vmcall;
		break;
	}

	vmx_instruction_handled(vmx);
	return 0;
}

static int (*const vmx_exit_handlers[])(struct sv_vcpu_vmx *vmx) = {
	[EXIT_REASON_CR_ACCESS] = handle_cr_access,
	[EXIT_REASON_CPUID]     = handle_cpuid,
	[EXIT_REASON_MSR_READ]  = handle_msr_read,
	[EXIT_REASON_VMCALL]    = handle_vmcall,
};

static void vmx_hypervisor(struct sv_vcpu_vmx *vmx)
{
	u32 exit_reason = vmcs_read32(VM_EXIT_REASON);

	vmx->exits.total++;

	// cannot handle this exit, just bail.
	// - vmfails are likely a result of lacking error checks, so we could
	//   roll-back changes from last vm exit and inject #GP instead
	// - unexpected vm exits could just drop the virtualization by loading
	//   guest state (not if you want to use it for "security" purposes)
	//   (Linux actually does it right now thanks to BUG(), but it is just
	//    very lucky coincidence)
	if (vmx->fail || exit_reason >= ARRAY_SIZE(vmx_exit_handlers) || !vmx_exit_handlers[exit_reason])
		vmx_bug(vmx);

	vmx_exit_handlers[exit_reason](vmx);
	vmx_vmresume(vmx);
	BUG(); /* should never get here */
}

void vmx_vmresume(struct sv_vcpu_vmx *vmx)
{
	asm (
			"mov %0, %%rsp \n\t"

			"mov %c[cr2](%%rsp), %%rax \n\t"
			"mov %%rax, %%cr2\n\t"

			"mov %c[rax](%%rsp), %%rax \n\t"
			"mov %c[rbx](%%rsp), %%rbx \n\t"
			"mov %c[rcx](%%rsp), %%rcx \n\t"
			"mov %c[rdx](%%rsp), %%rdx \n\t"
			"mov %c[rsi](%%rsp), %%rsi \n\t"
			"mov %c[rdi](%%rsp), %%rdi \n\t"
			"mov %c[rbp](%%rsp), %%rbp \n\t"
			"mov %c[r8](%%rsp),  %%r8  \n\t"
			"mov %c[r9](%%rsp),  %%r9  \n\t"
			"mov %c[r10](%%rsp), %%r10 \n\t"
			"mov %c[r11](%%rsp), %%r11 \n\t"
			"mov %c[r12](%%rsp), %%r12 \n\t"
			"mov %c[r13](%%rsp), %%r13 \n\t"
			"mov %c[r14](%%rsp), %%r14 \n\t"
			"mov %c[r15](%%rsp), %%r15 \n\t"

			__ex(ASM_VMX_VMRESUME) "\n\t"
			/* no need to store registers in case of an entry
			 * failure, but failures should never happen anyway */
			"1: "

			"mov %%rax, %c[rax](%%rsp) \n\t"
			"mov %%rbx, %c[rbx](%%rsp) \n\t"
			"mov %%rcx, %c[rcx](%%rsp) \n\t"
			"mov %%rdx, %c[rdx](%%rsp) \n\t"
			"mov %%rsi, %c[rsi](%%rsp) \n\t"
			"mov %%rdi, %c[rdi](%%rsp) \n\t"
			"mov %%rbp, %c[rbp](%%rsp) \n\t"
			"mov %%r8,  %c[r8](%%rsp) \n\t"
			"mov %%r9,  %c[r9](%%rsp) \n\t"
			"mov %%r10, %c[r10](%%rsp) \n\t"
			"mov %%r11, %c[r11](%%rsp) \n\t"
			"mov %%r12, %c[r12](%%rsp) \n\t"
			"mov %%r13, %c[r13](%%rsp) \n\t"
			"mov %%r14, %c[r14](%%rsp) \n\t"
			"mov %%r15, %c[r15](%%rsp) \n\t"

			"mov %%cr2, %%rax\n\t"
			"mov %%rax, %c[cr2](%%rsp) \n\t"

			"setbe %c[fail](%%rsp) \n\t"

			"mov %%rsp, %%rdi \n\t"
			"mov %c[host_rsp](%%rsp), %%rsp \n\t"
			"call %c[handler] \n\t"
			"ud2 \n\t"

			".pushsection .rodata \n\t"
			".global hypervisor_entry \n\t"
			"hypervisor_entry: " _ASM_PTR " 1b \n\t"
			".popsection"
	: :
		"r"(vmx),
		[fail]"i"(offsetof(struct sv_vcpu_vmx, fail)),
		[host_rsp]"i"(offsetof(struct sv_vcpu_vmx, host_rsp)),
		[rax]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_RBP])),
		[r8]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct sv_vcpu_vmx, regs[VCPU_REGS_R15])),
		[cr2]"i"(offsetof(struct sv_vcpu_vmx, guest_cr2)),
		[handler]"i"(vmx_hypervisor)
	);
	/* should never get here, which is why there is no clobber */
}

static int vmx_vmlaunch(struct sv_vcpu_vmx *vmx)
{
	int r;
	u8 error = 0;
	u64 rflags;

	preempt_disable();
	local_irq_disable();

	if ((r = load_current_state(vmx)))
		return r;

	vmcs_writel(GUEST_RIP, guest_entry);

	asm volatile ("pushfq; popq %0" : "=rm"(rflags) :: "memory");
	vmcs_writel(GUEST_RFLAGS, rflags);

	/* Host stack pointer is loaded after VM exit. */
	vmx->host_rsp = (u64)&hypervisor_stack[STACK_SIZE];
	vmcs_writel(HOST_RSP, (long)vmx);
	vmcs_writel(HOST_RIP, hypervisor_entry);

	asm volatile (
			"mov %%rsp, %%rax \n\t"
			__ex(ASM_VMX_VMWRITE_RAX_RDX)
			: : "d"(GUEST_RSP) : "rax", "cc");

	dump_vmcs();

	asm volatile (
			__ex(ASM_VMX_VMLAUNCH) "\n\t"
			"setbe %0 \n\t"
			"1: \n\t"
			".pushsection .rodata \n\t"
			".global guest_entry\n\t"
			"guest_entry: " _ASM_PTR " 1b \n\t" // .quad 1b
			".popsection"
			: "+q"(error) : : "cc", "memory");

	if (error)
		printk("VM entry error %x %d\n", error, vmcs_read32(VM_INSTRUCTION_ERROR));

	local_irq_enable();
	preempt_enable();
	return 0;
}

static int vmx_reflect(struct sv_vcpu_vmx *vmx)
{
	return vmx_vmlaunch(vmx);
}

int virtualize_self(void) {
	struct vmcs_config vmcs_conf;
	struct sv_vcpu_vmx *vmx = kzalloc(sizeof *vmx, GFP_KERNEL);
	int r;

	if ((r = vmx_setup_vmcs_config(&vmcs_conf)))
		return r;

	if ((r = vmx_hardware_enable(&vmcs_conf)))
		return r;

	if ((r = vmx_prepare_vcpu(vmx, &vmcs_conf)))
		return r;

	return vmx_reflect(vmx);
}
