#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/mm.h>

#include <asm/asm.h>
#include <asm/cpu.h>
#include <asm/vmx.h>
#include <asm/processor-flags.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>

#define EPTP_INDEX 0x00000004
#define VM_FUNCTION_CONTROL 0x00002018
#define EPTP_LIST_ADDRESS 0x00002024
#define XSS_EXIT_BITMAP 0x0000202c
#define ENCLS_EXITING_BITMAP 0x0000202e
#define GUEST_IA32_RTIT_CTL 0x00002814

#define IO_RCX	0x00006402
#define IO_RSI	0x00006404
#define IO_RDI	0x00006406
#define IO_RIP	0x00006408

#define page_phys_address(x) (page_to_pfn(x)*PAGE_SIZE)

#define VMX_AR_TYPE_READABLE_CODE_MASK (1 << 1)
#define VMX_AR_TYPE_WRITABLE_DATA_MASK (1 << 1)

/* EPTP Attributes. */
#define EPTP_CACHE_WB 0x6
#define EPTP_UNCACHEABLE 0x0
#define EPTP_PAGE_WALK_LEN(x) (((x)&0x7)<<3)
#define EPTP_ENABLE_A_D_FLAGS (1 << 6)
#define EPT_IGNORE_PAT (1 << 6)

/* EPT Attributes. */
#define EPT_PML4E_READ (1 << 0)
#define EPT_PML4E_WRITE (1 << 1)
#define EPT_PML4E_EXECUTE (1 << 2)
#define EPT_PML4E_ACCESS_FLAG (1 << 8)

#define EPT_PDPTE_READ (1 << 0)
#define EPT_PDPTE_WRITE (1 << 1)
#define EPT_PDPTE_EXECUTE (1 << 2)
#define EPT_PDPTE_UNCACHEABLE (0 << 3)
#define EPT_PDPTE_CACHE_WC (1 << 3)
#define EPT_PDPTE_CACHE_WT (4 << 3)
#define EPT_PDPTE_CACHE_WP (5 << 3)
#define EPT_PDPTE_CACHE_WB (6 << 3)
#define EPT_PDPTE_1GB_IGNORE_PAT (1 << 6)
#define EPT_PDPTE_1GB_PAGE (1 << 7)
#define EPT_PDPTE_ACCESS_FLAG (1 << 8)
#define EPT_PDPTE_DIRTY_FLAG (1 << 9)
#define EPT_PDPTE_1GB_PFN(x) ((x) & 0xffffffffc0000000)
#define EPT_PDPTE_1GB_OFFSET(x) ((x) & (~0xffffffffc0000000))

#define EPT_PDE_READ (1 << 0)
#define EPT_PDE_WRITE (1 << 1)
#define EPT_PDE_EXECUTE (1 << 2)
#define EPT_PDE_UNCACHEABLE (0 << 3)
#define EPT_PDE_CACHE_WC (1 << 3)
#define EPT_PDE_CACHE_WT (4 << 3)
#define EPT_PDE_CACHE_WP (5 << 3)
#define EPT_PDE_CACHE_WB (6 << 3)
#define EPT_PDE_2MB_IGNORE_PAT (1 << 6)
#define EPT_PDE_2MB_PAGE (1 << 7)
#define EPT_PDE_ACCESS_FLAG (1 << 8)
#define EPT_PDE_DIRTY_FLAG (1 << 9)
#define EPT_PDE_2MB_PFN(x) ((x) & 0xffffffffffe00000)
#define EPT_PDE_2MB_OFFSET(x) ((x) & (~0xffffffffffe00000))

#define EPT_PTE_READ (1 << 0)
#define EPT_PTE_WRITE (1 << 1)
#define EPT_PTE_EXECUTE (1 << 2)
#define EPT_PTE_UNCACHEABLE (0 << 3)
#define EPT_PTE_CACHE_WC (1 << 3)
#define EPT_PTE_CACHE_WT (4 << 3)
#define EPT_PTE_CACHE_WP (5 << 3)
#define EPT_PTE_CACHE_WB (6 << 3)
#define EPT_PTE_CACHE_IGNORE_PAT (1 << 6)
#define EPT_PTE_ACCESS_FLAG (1 << 8)
#define EPT_PTE_DIRTY_FLAG (1 << 9)
#define EPT_PT_4KB_PFN(x) ((x) & 0xfffffffffffff000)
#define EPT_PT_4KB_OFFSET(x) ((x) & (~0xfffffffffffff000))

#define PT_ENTRY_ADDR(x) ((x) & (~0xfff))

#define VMX_EPT_EXTENT_CONTEXT			1
#define VMX_EPT_EXTENT_GLOBAL			2
#define VMX_EPT_EXTENT_SHIFT			24

struct general_regs {
	u64 rax;
	u64 rbx;
	u64 rcx;
	u64 rdx;
	u64 rsi;
	u64 rdi;
	u64 rsp;
	u64 rbp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

struct ctrl_regs {
	u64 cr0;
	u64 cr2;
	u64 cr3;
	u64 cr4;
	u64 cr8;
	u64 xcr0;
};

struct debug_regs {
	u64 dr0;
	u64 dr1;
	u64 dr2;
	u64 dr3;
	u64 dr4;
	u64 dr5;
	u64 dr6;
	u64 dr7;
};

struct segment {
	u64 selector;
	u64 base;
	u64 limit;
	u64 ar_bytes;
};

struct gdtr {
	u16 limit;
	u64 base;
};

struct idtr {
	u16 limit;
	u64 base;
};

struct vmx_vcpu {
	int cpu;
	int launched;
	u32 virtual_processor_id;
	struct page *vmxon_region_pg;
	struct page *vmcs_pg;
	struct page *vmread_bitmap;
	struct page *vmwrite_bitmap;
	struct page *io_bitmap_a;
	struct page *io_bitmap_b;
	struct page *vapic_page;
	struct page *msr_bitmap;
	struct page *eptp_base;
	struct page *posted_intr_addr;
	int shadow_vmcs_enabled;
	struct page *host_msr;
	struct page *guest_msr;

	struct host_state {
		u16 ldt;
		u64 fs_base;
		u64 gs_base;
	} host_state;

	struct guest_state {
		u64 rip;
		u64 rflags;
		struct general_regs gr_regs;
		struct ctrl_regs ctrl_regs;
		struct segment cs, ds, es, fs, gs, ss, tr, ldtr;
		u64 cr0_read_shadow;
		u64 cr4_read_shadow;

		struct gdtr gdtr;
		struct idtr idtr;

		u64 *msr;
		u64 pdpte0;
		u64 pdpte1;
		u64 pdpte2;
		u64 pdpte3;

		u64 ia32_efer;

		struct page *guest_memory;
		int guest_memory_order;
	} guest_state;

	struct vmx_cap_msrs {
		u32 vmx_basic;
		u32 pin_based_allow1_mask;
		u32 pin_based_allow0_mask;
		u32 cpu_based_allow1_mask;
		u32 cpu_based_allow0_mask;
		u32 cpu_based2_allow1_mask;
		u32 cpu_based2_allow0_mask;
		u32 vm_entry_allow1_mask;
		u32 vm_entry_allow0_mask;
		u32 vm_exit_allow1_mask;
		u32 vm_exit_allow0_mask;
		u32 vmx_misc;
		u64 vmx_cr0_fixed0;
		u64 vmx_cr0_fixed1;
		u64 vmx_cr4_fixed0;
		u64 vmx_cr4_fixed1;
		u32 vmx_vmcs_enum;
		u32 vmx_ept_vpid_cap;
		u32 vmx_true_pinbased_ctls_l;
		u32 vmx_true_pinbased_ctls_h;
		u32 vmx_true_procbased_ctls_l;
		u32 vmx_true_procbased_ctls_h;
		u32 vmx_true_exit_ctls_l;
		u32 vmx_true_exit_ctls_h;
		u32 vmx_true_entry_ctls_l;
		u32 vmx_true_entry_ctls_h;
	} vmx_cap_msrs;
	
} *vcpu;

u64 vmcs_16bit_ctrl_fields[] = {
	VIRTUAL_PROCESSOR_ID,
	POSTED_INTR_NV,
	EPTP_INDEX
};

u64 vmcs_16bit_guest_state_fields[] = {
	GUEST_ES_SELECTOR,
	GUEST_CS_SELECTOR,
	GUEST_SS_SELECTOR,
	GUEST_DS_SELECTOR,
	GUEST_FS_SELECTOR,
	GUEST_GS_SELECTOR,
	GUEST_LDTR_SELECTOR,
	GUEST_TR_SELECTOR,
	GUEST_INTR_STATUS,
	GUEST_PML_INDEX
};

u64 vmcs_16bit_host_state_fields[] = {
	HOST_ES_SELECTOR,
	HOST_CS_SELECTOR,
	HOST_SS_SELECTOR,
	HOST_DS_SELECTOR,
	HOST_FS_SELECTOR,
	HOST_GS_SELECTOR,
	HOST_TR_SELECTOR
};

u64 vmcs_64bit_ctrl_fields[] = {
	IO_BITMAP_A,
	IO_BITMAP_B,
	MSR_BITMAP,
	VM_EXIT_MSR_STORE_ADDR,
	VM_EXIT_MSR_LOAD_ADDR,
	VM_ENTRY_MSR_LOAD_ADDR,
	PML_ADDRESS,
	TSC_OFFSET,
	VIRTUAL_APIC_PAGE_ADDR,
	APIC_ACCESS_ADDR,
	POSTED_INTR_DESC_ADDR,
	VM_FUNCTION_CONTROL,
	EPT_POINTER,
	EOI_EXIT_BITMAP0,
	EOI_EXIT_BITMAP1,
	EOI_EXIT_BITMAP2,
	EOI_EXIT_BITMAP3,
	EPTP_LIST_ADDRESS,
	VMREAD_BITMAP,
	VMWRITE_BITMAP,
	XSS_EXIT_BITMAP,
	ENCLS_EXITING_BITMAP,
	TSC_MULTIPLIER
};

u64 vmcs_64bit_readonly_fields[] = {
	GUEST_PHYSICAL_ADDRESS
};

u64 vmcs_64bit_guest_state_fields[] = {
	VMCS_LINK_POINTER,
	GUEST_IA32_DEBUGCTL,
	GUEST_IA32_PAT,
	GUEST_IA32_EFER,
	GUEST_IA32_PERF_GLOBAL_CTRL,
	GUEST_PDPTR0,
	GUEST_PDPTR1,
	GUEST_PDPTR2,
	GUEST_PDPTR3,
	GUEST_BNDCFGS,
	GUEST_IA32_RTIT_CTL
};

u64 vmcs_64bit_host_state_fields[] = {
	HOST_IA32_PAT,
	HOST_IA32_EFER,
	HOST_IA32_PERF_GLOBAL_CTRL,
};

u64 vmcs_32bit_ctrl_fields[] = {
	PIN_BASED_VM_EXEC_CONTROL,
	CPU_BASED_VM_EXEC_CONTROL,
	EXCEPTION_BITMAP,
	PAGE_FAULT_ERROR_CODE_MASK,
	PAGE_FAULT_ERROR_CODE_MATCH,
	CR3_TARGET_COUNT,
	VM_EXIT_CONTROLS,
	VM_EXIT_MSR_STORE_COUNT,
	VM_EXIT_MSR_LOAD_COUNT,
	VM_ENTRY_CONTROLS,
	VM_ENTRY_MSR_LOAD_COUNT,
	VM_ENTRY_INTR_INFO_FIELD,
	VM_ENTRY_EXCEPTION_ERROR_CODE,
	VM_ENTRY_INSTRUCTION_LEN,
	TPR_THRESHOLD,
	SECONDARY_VM_EXEC_CONTROL,
	PLE_GAP,
	PLE_WINDOW
};

u64 vmcs_32bit_readonly_fields[] = {
	VM_INSTRUCTION_ERROR,
	VM_EXIT_REASON,
	VM_EXIT_INTR_INFO,
	VM_EXIT_INTR_ERROR_CODE,
	IDT_VECTORING_INFO_FIELD,
	IDT_VECTORING_ERROR_CODE,
	VM_EXIT_INSTRUCTION_LEN,
	VMX_INSTRUCTION_INFO
};

u64 vmcs_32bit_guest_state_fields[] = {
	GUEST_ES_LIMIT,
	GUEST_CS_LIMIT,
	GUEST_SS_LIMIT,
	GUEST_DS_LIMIT,
	GUEST_FS_LIMIT,
	GUEST_GS_LIMIT,
	GUEST_LDTR_LIMIT,
	GUEST_TR_LIMIT,
	GUEST_GDTR_LIMIT,
	GUEST_IDTR_LIMIT,
	GUEST_ES_AR_BYTES,
	GUEST_CS_AR_BYTES,
	GUEST_SS_AR_BYTES,
	GUEST_DS_AR_BYTES,
	GUEST_FS_AR_BYTES,
	GUEST_GS_AR_BYTES,
	GUEST_LDTR_AR_BYTES,
	GUEST_TR_AR_BYTES,
	GUEST_INTERRUPTIBILITY_INFO,
	GUEST_ACTIVITY_STATE,
	GUEST_SYSENTER_CS,
	VMX_PREEMPTION_TIMER_VALUE
};

u64 vmcs_32bit_host_state_field[] = {
	HOST_IA32_SYSENTER_CS
};

u64 vmcs_natural_width_ctrl_fields[] = {
	CR0_GUEST_HOST_MASK,
	CR4_GUEST_HOST_MASK,
	CR0_READ_SHADOW,
	CR4_READ_SHADOW,
	CR3_TARGET_VALUE0,
	CR3_TARGET_VALUE1,
	CR3_TARGET_VALUE2,
	CR3_TARGET_VALUE3
};

u64 vmcs_natural_width_readonly_fields[] = {
	EXIT_QUALIFICATION,
	IO_RCX,
	IO_RSI,
	IO_RDI,
	IO_RIP,
	GUEST_LINEAR_ADDRESS
};

u64 vmcs_natural_width_guest_state_fields[] = {
	GUEST_CR0,
	GUEST_CR3,
	GUEST_CR4,
	GUEST_ES_BASE,
	GUEST_CS_BASE,
	GUEST_SS_BASE,
	GUEST_DS_BASE,
	GUEST_FS_BASE,
	GUEST_GS_BASE,
	GUEST_LDTR_BASE,
	GUEST_TR_BASE,
	GUEST_GDTR_BASE,
	GUEST_IDTR_BASE,
	GUEST_DR7,
	GUEST_RSP,
	GUEST_RIP,
	GUEST_RFLAGS,
	GUEST_PENDING_DBG_EXCEPTIONS,
	GUEST_SYSENTER_ESP,
	GUEST_SYSENTER_EIP,
};

u64 vmcs_natural_width_host_state_fields[] = {
	HOST_CR0,
	HOST_CR3,
	HOST_CR4,
	HOST_FS_BASE,
	HOST_GS_BASE,
	HOST_TR_BASE,
	HOST_GDTR_BASE,
	HOST_IDTR_BASE,
	HOST_IA32_SYSENTER_ESP,
	HOST_IA32_SYSENTER_EIP,
	HOST_RSP,
	HOST_RIP
};
