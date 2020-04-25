#include "vmx.h"

void serial_debug(char ch)
{
	asm volatile (
		"mov $0x3f8, %%dx \n\t"
		"mov %0, %%al \n\t"
		"outb %%al, %%dx \n\t"
		:
		:"r"(ch)
		:"rdx"
	);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,10,0)
u64 read_cr3(void)
{
	return __read_cr3();
}

u64 read_cr4(void)
{
	return cr4_read_shadow();
}

void write_cr4(u64 val)
{
	cr4_set_bits(val);
}
#else
void cr4_set_bits(u64 val)
{
	u64 cr4 = read_cr4();
	cr4 |= val;
	write_cr4(cr4);
}

void cr4_clear_bits(u64 val)
{
	u64 cr4 = read_cr4();
	cr4 ^= val;
	write_cr4(cr4);
}

static DEFINE_PER_CPU(struct desc_ptr, host_gdt);
void *get_current_gdt_ro(void)
{
	struct desc_ptr *gdt;
	native_store_gdt(this_cpu_ptr(&host_gdt));
	gdt = &__get_cpu_var(host_gdt);
	return gdt->address;
}

#define EXIT_REASON_RDRAND              57
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_VMFUNC              59
#define EXIT_REASON_ENCLS               60
#define EXIT_REASON_RDSEED              61

#define SECONDARY_EXEC_RDRAND_EXITING 0x00000800
#define SECONDARY_EXEC_RDSEED_EXITING 0x00010000

#endif

static inline u16 kvm_read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

static inline void kvm_load_ldt(u16 sel)
{
	asm("lldt %0" : :"rm"(sel));
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static unsigned long segment_base(u16 selector)
{
	struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = kvm_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);
#ifdef CONFIG_X86_64
       if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
               v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;
#endif
	return v;
}
#endif

static inline u64 kvm_read_tr_base(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,10,0)
	return (u64)&get_cpu_entry_area(smp_processor_id())->tss.x86_tss;
#else
	u16 tr;
	asm("str %0" : "=g"(tr));
	return segment_base(tr);
#endif	
}

static __always_inline void __vmxon(u64 addr)
{
	asm volatile("vmxon %0 \n\t" : :"m"(addr));
}

static __always_inline void __vmclear(u64 addr)
{
	asm volatile("vmclear %0 \n\t" : :"m"(addr));
}

static __always_inline void __vmptrld(u64 addr)
{
	asm volatile("vmptrld %0 \n\t" : :"m"(addr));
}

static __always_inline void __vmptrst(u64 *addr)
{
	asm volatile("vmptrst (%0) \n\t" : :"r"(addr));
}

static __always_inline u64 __vmread(u64 field)
{
	u64 ret;
	u8 flag;
	asm volatile("vmread %2, %0 \n\t"
		"setbe %1 \n\t"
		:"=a"(ret),"=r"(flag) :"r"(field));
	if (flag) {
		printk("vmread failed.field = %llx\n", field);
	}
	return ret;
}

static __always_inline int __vmwrite(u64 field, u64 value)
{
	u8 flag;
	asm volatile("vmwrite %2, %1 \n\t"
		"setbe %0 \n\t"
	:"=r"(flag)
	:"r"(field), "r"(value));

	if (flag) {
		printk("vmwrite failed.field = %llx\n", field);
	}

	return 0;
}

int __vmx_vcpu_run(struct vmx_vcpu *vcpu)
{
	struct general_regs *gr_regs = &vcpu->guest_state.gr_regs;
	int ret;

	asm volatile(
		"mov %%eax, %0 \n\t"
		"push %%rbx \n\t"
		"push %%rbp \n\t"
		"push %%r12 \n\t"
		"push %%r13 \n\t"
		"push %%r14 \n\t"
		"push %%r15 \n\t"
		"push %%rdi \n\t"
		"push %1 \n\t"
		"mov $0x00006c14, %%r8 \n\t" //HOST_RSP
		"vmwrite %%rsp, %%r8 \n\t"
		"mov %2, %%esp \n\t"
		"mov %1, %%r15 \n\t"
		"mov 0x0(%%r15), %%rax \n\t"
		"mov 0x8(%%r15), %%rbx \n\t"
		"mov 0x10(%%r15), %%rcx \n\t"
		"mov 0x18(%%r15), %%rdx \n\t"
		"mov 0x20(%%r15), %%rsi \n\t"
		"mov 0x28(%%r15), %%rdi \n\t"
		//"mov 0x30(%%r15), %%rsp \n\t"
		"mov 0x38(%%r15), %%rbp \n\t"
		"mov 0x40(%%r15), %%r8 \n\t"
		"mov 0x48(%%r15), %%r9 \n\t"
		"mov 0x50(%%r15), %%r10 \n\t"
		"mov 0x58(%%r15), %%r11 \n\t"
		"mov 0x60(%%r15), %%r12 \n\t"
		"mov 0x68(%%r15), %%r13 \n\t"
		"mov 0x70(%%r15), %%r14 \n\t"
		"mov 0x78(%%r15), %%r15 \n\t"

		"cmp $0, %%rsp \n\t"
		"jnz _vm_resume \n\t"
		"vmlaunch \n\t"
		"setbe %%al \n\t"
		"jmp _vm_fail \n\t"
	"_vm_resume: \n\t"
		"vmresume \n\t"
	"_vm_fail: \n\t"
		"setbe %%al \n\t"
		"mov $0x00006c14, %%r8 \n\t" //HOST_RSP
		"vmread %%r8, %%rsp \n\t"
		"pop %1 \n\t"
		"pop %%rdi \n\t"
		"pop %%r15 \n\t"
		"pop %%r14 \n\t"
		"pop %%r13 \n\t"
		"pop %%r12 \n\t"
		"pop %%rbp \n\t"
		"pop %%rbx \n\t"
		"mov %%eax, %0 \n\t"
		"jmp _vm_end \n\t"
	"vm_exit_point: \n\t"
		"push %%r15 \n\t"
		"mov 0x8(%%rsp), %%r15 \n\t"
		"mov %%rax, 0x0(%%r15) \n\t"
		"mov %%rbx, 0x8(%%r15) \n\t"
		"mov %%rcx, 0x10(%%r15) \n\t"
		"mov %%rdx, 0x18(%%r15) \n\t"
		"mov %%rsi, 0x20(%%r15) \n\t"
		"mov %%rdi, 0x28(%%r15) \n\t"
		//"mov %%rsp, 0x30(%%r15) \n\t"
		"mov %%rbp, 0x38(%%r15) \n\t"
		"mov %%r8, 0x40(%%r15) \n\t"
		"mov %%r9, 0x48(%%r15) \n\t"
		"mov %%r10, 0x50(%%r15) \n\t"
		"mov %%r11, 0x58(%%r15) \n\t"
		"mov %%r12, 0x60(%%r15) \n\t"
		"mov %%r13, 0x68(%%r15) \n\t"
		"mov %%r14, 0x70(%%r15) \n\t"

		"pop %%rax \n\t"
		"mov %%rax, 0x78(%%r15) \n\t"

		"pop %1 \n\t"
		"pop %%rdi \n\t"
		"pop %%r15 \n\t"
		"pop %%r14 \n\t"
		"pop %%r13 \n\t"
		"pop %%r12 \n\t"
		"pop %%rbp \n\t"
		"pop %%rbx \n\t"

	"_vm_end: \n\t"
		:"=m"(ret)
		:"r"(gr_regs),"r"(vcpu->launched)
		:"rax","rcx","rdx","rsi","r8","r9","r10"
	);

	if (ret == 0)
		vcpu->launched = 1;

	return ret;
}

static inline void __invept(unsigned long ext, u64 eptp, u64 gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = {eptp, gpa};

	asm volatile ("invept %1, %0"
		      :: "r"(ext), "m"(operand));
}

static __always_inline void __vmxoff(void)
{
	asm volatile("vmxoff \n\t");
}

int vmx_hardware_enable(struct vmx_vcpu *vcpu)
{
	u64 *vmxon_region_ptr;
	u32 msr_l, msr_h;
	int cpu = raw_smp_processor_id();

	if (read_cr4() & X86_CR4_VMXE) {
		printk("VMXE already enabled on CPU %d.Close running QEMU first.\n", cpu);
		return -1;
	}

	cr4_set_bits(X86_CR4_VMXE);
	rdmsr(MSR_IA32_VMX_BASIC, msr_l, msr_h);
	vmxon_region_ptr = page_address(vcpu->vmxon_region_pg);
	vmxon_region_ptr[0] = msr_l;
	__vmxon(page_phys_address(vcpu->vmxon_region_pg));
	vcpu->cpu = cpu;
	printk("enabling VTx on CPU %d succeeded.\n", cpu);
	return 0;
}

void vmx_hardware_disable(void *para)
{
	struct vmx_vcpu *vcpu = para;
	u64 vmcs_phys = page_to_pfn(vcpu->vmcs_pg) * PAGE_SIZE;
	int cpu = raw_smp_processor_id();
	if ((read_cr4() & X86_CR4_VMXE) == 0) {
		printk("VMXE already disabled on CPU %d.\n", cpu);
		return;
	}

	__vmclear(vmcs_phys);
	__vmxoff();
	cr4_clear_bits(X86_CR4_VMXE);
	printk("disabling VTx on CPU %d succeeded.\n", cpu);
}

static void vmx_msrs_detect(struct vmx_vcpu *vcpu)
{
	u32 msr_l, msr_h;
	u64 msr;
	rdmsr(MSR_IA32_VMX_BASIC, msr_l, msr_h);
	printk("MSR_IA32_VMX_BASIC:0x%x 0x%x\n", msr_l, msr_h);
	vcpu->vmx_cap_msrs.vmx_basic = msr_l;
	
	rdmsr(MSR_IA32_VMX_PINBASED_CTLS, msr_l, msr_h);
	vcpu->vmx_cap_msrs.pin_based_allow0_mask = msr_l;
	vcpu->vmx_cap_msrs.pin_based_allow1_mask = msr_h;
	printk("MSR_IA32_VMX_PINBASED_CTLS:0x%x 0x%x\n", msr_l, msr_h);

	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS, msr_l, msr_h);
	vcpu->vmx_cap_msrs.cpu_based_allow0_mask = msr_l;
	vcpu->vmx_cap_msrs.cpu_based_allow1_mask = msr_h;
	printk("MSR_IA32_VMX_PROCBASED_CTLS:0x%x 0x%x\n", msr_l, msr_h);

	rdmsr(MSR_IA32_VMX_EXIT_CTLS, msr_l, msr_h);
	vcpu->vmx_cap_msrs.vm_exit_allow0_mask = msr_l;
	vcpu->vmx_cap_msrs.vm_exit_allow1_mask = msr_h;
	printk("MSR_IA32_VMX_EXIT_CTLS:0x%x 0x%x\n", msr_l, msr_h);

	rdmsr(MSR_IA32_VMX_ENTRY_CTLS, msr_l, msr_h);
	vcpu->vmx_cap_msrs.vm_entry_allow0_mask = msr_l;
	vcpu->vmx_cap_msrs.vm_entry_allow1_mask = msr_h;
	printk("MSR_IA32_VMX_ENTRY_CTLS:0x%x 0x%x\n", msr_l, msr_h);

	rdmsr(MSR_IA32_VMX_MISC, msr_l, msr_h);
	vcpu->vmx_cap_msrs.vmx_misc = msr_l;
	printk("MSR_IA32_VMX_MISC:0x%x 0x%x\n", msr_l, msr_h);

	rdmsrl(MSR_IA32_VMX_CR0_FIXED0, msr);
	vcpu->vmx_cap_msrs.vmx_cr0_fixed0 = msr;
	printk("MSR_IA32_VMX_CR0_FIXED0:0x%llx\n", msr);

	rdmsrl(MSR_IA32_VMX_CR0_FIXED1, msr);
	vcpu->vmx_cap_msrs.vmx_cr0_fixed1 = msr;
	printk("MSR_IA32_VMX_CR0_FIXED1:0x%llx\n", msr);

	rdmsrl(MSR_IA32_VMX_CR4_FIXED0, msr);
	vcpu->vmx_cap_msrs.vmx_cr4_fixed0 = msr;
	printk("MSR_IA32_VMX_CR4_FIXED0:0x%llx\n", msr);

	rdmsrl(MSR_IA32_VMX_CR4_FIXED1, msr);
	vcpu->vmx_cap_msrs.vmx_cr4_fixed1 = msr;
	printk("MSR_IA32_VMX_CR4_FIXED1:0x%llx\n", msr);

	rdmsr(MSR_IA32_VMX_VMCS_ENUM, msr_l, msr_h);
	vcpu->vmx_cap_msrs.vmx_vmcs_enum = msr_l;
	printk("MSR_IA32_VMX_VMCS_ENUM:0x%x 0x%x\n", msr_l, msr_h);

	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2, msr_l, msr_h);
	vcpu->vmx_cap_msrs.cpu_based2_allow0_mask = msr_l;
	vcpu->vmx_cap_msrs.cpu_based2_allow1_mask = msr_h;
	printk("MSR_IA32_VMX_PROCBASED_CTLS2:0x%x 0x%x\n", msr_l, msr_h);

	rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, msr_l, msr_h);
	printk("MSR_IA32_VMX_EPT_VPID_CAP:0x%x 0x%x\n", msr_l, msr_h);
	rdmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS, msr_l, msr_h);
	printk("MSR_IA32_VMX_TRUE_PINBASED_CTLS:0x%x 0x%x\n", msr_l, msr_h);
	rdmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS, msr_l, msr_h);
	printk("MSR_IA32_VMX_TRUE_PROCBASED_CTLS:0x%x 0x%x\n", msr_l, msr_h);
	rdmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS, msr_l, msr_h);
	printk("MSR_IA32_VMX_TRUE_EXIT_CTLS:0x%x 0x%x\n", msr_l, msr_h);
	rdmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS, msr_l, msr_h);
	printk("MSR_IA32_VMX_TRUE_ENTRY_CTLS:0x%x 0x%x\n", msr_l, msr_h);
	rdmsr(MSR_IA32_VMX_VMFUNC, msr_l, msr_h);
	printk("MSR_IA32_VMX_VMFUNC:0x%x 0x%x\n", msr_l, msr_h);
	
}

static void vmcs_layout_detect(struct vmx_vcpu *vcpu, u64 *vmcs_fields, int size, int width)
{
	int i, j;
	int ret;
	u64 value;
	u64 value_1;
	u16 *vmcs_ptr_16 = page_address(vcpu->vmcs_pg);
	u32 *vmcs_ptr_32 = page_address(vcpu->vmcs_pg);
	u64 *vmcs_ptr_64 = page_address(vcpu->vmcs_pg);
	u64 *vmcs_ptr = page_address(vcpu->vmcs_pg);

	u32 msr_l, msr_h;

	if (width == 2)
		value = 0x55aa;
	else if (width == 4)
		value = 0x93;
	else
		value = 0x123455aa;

	rdmsr(MSR_IA32_VMX_BASIC, msr_l, msr_h);
	for (i = 0; i < size; i++) {
		memset(vmcs_ptr, 0, PAGE_SIZE);
		vmcs_ptr[0] = msr_l;
		__vmclear(page_phys_address(vcpu->vmcs_pg));
		__vmptrld(page_phys_address(vcpu->vmcs_pg));
		ret = __vmwrite(vmcs_fields[i], value);
		value_1 = __vmread(vmcs_fields[i]);

		if (ret) {
			printk("field %llx offset:vmwrite failed.\n", vmcs_fields[i]);
			continue;
		}

		if (value_1 != value) {
			printk("field %llx offset:unsupported value.\n", vmcs_fields[i]);
			continue;
		}
		__vmclear(page_phys_address(vcpu->vmcs_pg));

		if (width == 2) {
			for (j = 0; j < 0x1000 / 2; j++) {
				if (vmcs_ptr_16[j] == value) {
					printk("field %llx offset:%x\n", vmcs_fields[i], j * 2);
					break;
				}
			}
			if (j == 0x1000 / 2)
				printk("field %llx offset:uknown.\n", vmcs_fields[i]);
		} else if (width == 4) {
			for (j = 0; j < 0x1000 / 4; j++) {
				if (vmcs_ptr_32[j] == value) {
					printk("field %llx offset:%x\n", vmcs_fields[i], j * 4);
					break;
				}
			}
			if (j == 0x1000 / 4)
				printk("field %llx offset:uknown.\n", vmcs_fields[i]);
		} else {
			for (j = 0; j < 0x1000 / 8; j++) {
				if (vmcs_ptr_64[j] == value) {
					printk("field %llx offset:%x\n", vmcs_fields[i], j * 8);
					break;
				}
			}
			if (j == 0x1000 / 8)
				printk("field %llx offset:uknown.\n", vmcs_fields[i]);
		}
	};
	
}

int ept_map_page(struct page *eptp_base, u64 gpa, u64 hpa, u64 page_size, u64 attribute)
{
	//printk("ept map:gpa = %x hpa = %x page_size = %x\n", gpa, hpa, page_size);
	u64 index1, index2, index3, index4, offset_1g, offset_2m, offset_4k;
	u64 *pml4t, *pdpt, *pdt, *pt;
	u64 pml4e, pdpte, pde, pte;
	u64 pml4e_attr, pdpte_attr, pde_attr, pte_attr;
	u64 *virt;
	struct page *page;
	pml4e_attr = EPT_PML4E_READ | EPT_PML4E_WRITE | EPT_PML4E_EXECUTE | EPT_PML4E_ACCESS_FLAG;
	pdpte_attr = EPT_PDPTE_READ | EPT_PDPTE_WRITE | EPT_PDPTE_EXECUTE | EPT_PDPTE_ACCESS_FLAG;
	pde_attr = EPT_PDE_READ | EPT_PDE_WRITE | EPT_PDE_EXECUTE | EPT_PDE_ACCESS_FLAG;
	pte_attr = EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_ACCESS_FLAG;
	pml4t = page_address(eptp_base);

	index1 = (gpa >> 39) & 0x1ff;
	index2 = (gpa >> 30) & 0x1ff;
	index3 = (gpa >> 21) & 0x1ff;
	index4 = (gpa >> 12) & 0x1ff;
	offset_1g = gpa & ((1 << 30) - 1);
	offset_2m = gpa & ((1 << 21) - 1);
	offset_4k = gpa & ((1 << 12) - 1);

	pml4e = pml4t[index1];
	if (pml4e == 0) {
		page = alloc_pages(GFP_KERNEL, 0);
		virt = page_address(page);
		memset(virt, 0, PAGE_SIZE);
		pml4t[index1] = page_phys_address(page) | pml4e_attr;
	}

	pdpt = page_address(pfn_to_page(PT_ENTRY_ADDR(pml4t[index1]) >> 12));
	pdpte = pdpt[index2];

	if (page_size == 0x40000000) {
		pdpt[index2] = hpa | attribute | EPT_PDPTE_1GB_PAGE;
		return 0;
	}

	if (pdpte == 0) {
		page = alloc_pages(GFP_KERNEL, 0);
		virt = page_address(page);
		memset(virt, 0, PAGE_SIZE);
		pdpt[index2] = page_phys_address(page) | pdpte_attr;
	}

	pdt = page_address(pfn_to_page(PT_ENTRY_ADDR(pdpt[index2]) >> 12));
	pde = pdt[index3];

	if (page_size == 0x200000) {
		pdt[index3] = hpa | attribute | EPT_PDE_2MB_PAGE;
		return 0;
	}

	if (pde == 0) {
		page = alloc_pages(GFP_KERNEL, 0);
		virt = page_address(page);
		memset(virt, 0, PAGE_SIZE);
		pdt[index3] = page_phys_address(page) | pde_attr;
	}

	pt = page_address(pfn_to_page(PT_ENTRY_ADDR(pdt[index3]) >> 12));
	pte = pdt[index4];

	if (page_size == 0x1000) {
		pt[index4] = hpa | attribute;
		return 0;
	}
	
	return 0;
}

static void free_ept_page(struct page *eptp_base, int level)
{
	int i;
	u64 *page_table = page_address(eptp_base);
	for (i = 0; i < 512; i++) {
		if (PT_ENTRY_ADDR(page_table[i]) != 0) {
			if ((level < 2) && ((page_table[i] & (1 << 7)) == 0))
				free_ept_page(pfn_to_page(PT_ENTRY_ADDR(page_table[i]) / PAGE_SIZE), level + 1);
			free_pages(page_address(pfn_to_page(PT_ENTRY_ADDR(page_table[i]) / PAGE_SIZE)), 0);
			//printk("ept free, level = %d, addr = 0x%llx\n", level, page_table[i]);
		}
	}
}

static void vmx_mem_alloc(struct vmx_vcpu *vcpu)
{
	vcpu->vmxon_region_pg = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->vmxon_region_pg), 0, PAGE_SIZE);
	vcpu->vmcs_pg = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->vmcs_pg), 0, PAGE_SIZE);
	vcpu->posted_intr_addr = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->posted_intr_addr), 0, PAGE_SIZE);
	vcpu->io_bitmap_a = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->io_bitmap_a), 0, PAGE_SIZE);
	vcpu->io_bitmap_b = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->io_bitmap_b), 0, PAGE_SIZE);
	vcpu->msr_bitmap = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->msr_bitmap), 0, PAGE_SIZE);
	vcpu->host_msr = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->host_msr), 0x0, PAGE_SIZE);
	vcpu->guest_msr = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->guest_msr), 0x0, PAGE_SIZE);
	vcpu->eptp_base = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->eptp_base), 0, PAGE_SIZE);
	vcpu->vapic_page = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->vapic_page), 0, PAGE_SIZE);
	vcpu->vmread_bitmap = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->vmread_bitmap), 0x0, PAGE_SIZE);
	vcpu->vmwrite_bitmap = alloc_pages(GFP_KERNEL, 0);
	memset(page_address(vcpu->vmwrite_bitmap), 0x0, PAGE_SIZE);
}

static void vmx_mem_free(struct vmx_vcpu *vcpu)
{
	free_pages((long)page_address(vcpu->vmxon_region_pg), 0);
	free_pages((long)page_address(vcpu->vmcs_pg), 0);
	free_pages((long)page_address(vcpu->posted_intr_addr), 0);
	free_pages((long)page_address(vcpu->io_bitmap_a), 0);
	free_pages((long)page_address(vcpu->io_bitmap_b), 0);
	free_pages((long)page_address(vcpu->msr_bitmap), 0);
	free_pages((long)page_address(vcpu->host_msr), 0);
	free_pages((long)page_address(vcpu->guest_msr), 0);
	free_pages((long)page_address(vcpu->eptp_base), 0);
	free_pages((long)page_address(vcpu->vapic_page), 0);
	free_pages((long)page_address(vcpu->vmread_bitmap), 0);
	free_pages((long)page_address(vcpu->vmwrite_bitmap), 0);
}

static int alloc_guest_memory(struct vmx_vcpu *vcpu, u64 gpa, int pg_cnt_order)
{
	u64 phys;
	int i;
	vcpu->guest_state.guest_memory = alloc_pages(GFP_ATOMIC, pg_cnt_order);
	vcpu->guest_state.guest_memory_order = pg_cnt_order;
	if (vcpu->guest_state.guest_memory == NULL) {
		printk("allocate guest memory failed. order = %d\n", pg_cnt_order);
		return -ENOMEM;
	}
	memset(page_address(vcpu->guest_state.guest_memory), 0, (1 << pg_cnt_order));
	phys = page_to_pfn(vcpu->guest_state.guest_memory) * PAGE_SIZE;
	for (i = 0; i < (1 << pg_cnt_order); i++) {
		ept_map_page(vcpu->eptp_base,
			i * PAGE_SIZE,
			phys + i * PAGE_SIZE,
			0x1000,
			EPT_PTE_READ | EPT_PTE_WRITE | EPT_PTE_EXECUTE | EPT_PTE_CACHE_WB
		);
	}
	return 0;
}

static void copy_code_to_guest(struct vmx_vcpu *vcpu)
{
	extern u64 test_guest, test_guest_end;
	u8 *guest_memory = page_address(vcpu->guest_state.guest_memory);
	u64 *page_ptr;

	__builtin_memcpy(guest_memory + 0x7c00, &test_guest, (u64)&test_guest_end - (u64)&test_guest);
	// Setup guest page table for directly stepping into longmode.
	page_ptr = (u64 *)(guest_memory + 0x10000);
	page_ptr[0] = 0x11003;
	page_ptr = (u64 *)(guest_memory + 0x11000);
	page_ptr[0] = 0x83;
}

static void vmx_ctrl_setup(struct vmx_vcpu *vcpu)
{
	u64 *vmcs_ptr = page_address(vcpu->vmcs_pg);

	u64 pin_based_vm_exec_ctrl;
	u64 cpu_based_vm_exec_ctrl;
	u64 cpu_based_vm_exec_ctrl2;
	u64 vm_entry_ctrl;
	u64 vm_exit_ctrl;

	memset(vmcs_ptr, 0, PAGE_SIZE);
	vmcs_ptr[0] = vcpu->vmx_cap_msrs.vmx_basic;
	__vmclear(page_phys_address(vcpu->vmcs_pg));
	__vmptrld(page_phys_address(vcpu->vmcs_pg));

	vcpu->virtual_processor_id = 0x4;
	__vmwrite(VIRTUAL_PROCESSOR_ID, vcpu->virtual_processor_id);

	pin_based_vm_exec_ctrl = PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR
		| PIN_BASED_EXT_INTR_MASK
		| PIN_BASED_POSTED_INTR
		//| PIN_BASED_VMX_PREEMPTION_TIMER
		;

	//__vmwrite(VMX_PREEMPTION_TIMER_VALUE, 2100000000 / 128);

	if ((pin_based_vm_exec_ctrl | vcpu->vmx_cap_msrs.pin_based_allow1_mask) != vcpu->vmx_cap_msrs.pin_based_allow1_mask) {
		printk("Warning:setting pin_based_vm_exec_control:%llx unsupported.\n", 
			(pin_based_vm_exec_ctrl & vcpu->vmx_cap_msrs.pin_based_allow1_mask) ^ pin_based_vm_exec_ctrl);
		pin_based_vm_exec_ctrl |= vcpu->vmx_cap_msrs.pin_based_allow0_mask;
		pin_based_vm_exec_ctrl &= vcpu->vmx_cap_msrs.pin_based_allow1_mask;
	}

	if (pin_based_vm_exec_ctrl & PIN_BASED_POSTED_INTR) {
		__vmwrite(POSTED_INTR_DESC_ADDR, page_phys_address(vcpu->posted_intr_addr));
	}
	printk("pin_based_vm_exec_ctrl:%llx\n", pin_based_vm_exec_ctrl);
	__vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_ctrl);

	cpu_based_vm_exec_ctrl = 0x4006172
		| CPU_BASED_ACTIVATE_SECONDARY_CONTROLS
		//| CPU_BASED_USE_IO_BITMAPS
		| CPU_BASED_USE_MSR_BITMAPS
		| CPU_BASED_TPR_SHADOW
		| CPU_BASED_UNCOND_IO_EXITING
		| CPU_BASED_HLT_EXITING
		//| CPU_BASED_CR3_LOAD_EXITING
		//| CPU_BASED_MONITOR_TRAP_FLAG
		;
	if ((cpu_based_vm_exec_ctrl | vcpu->vmx_cap_msrs.cpu_based_allow1_mask) != vcpu->vmx_cap_msrs.cpu_based_allow1_mask) {
		printk("Warning:setting cpu_based_vm_exec_control:%llx unsupported.\n", 
			(cpu_based_vm_exec_ctrl & vcpu->vmx_cap_msrs.cpu_based_allow1_mask) ^ cpu_based_vm_exec_ctrl);
		cpu_based_vm_exec_ctrl |= vcpu->vmx_cap_msrs.cpu_based_allow0_mask;
		cpu_based_vm_exec_ctrl &= vcpu->vmx_cap_msrs.cpu_based_allow1_mask;
	}

	if (cpu_based_vm_exec_ctrl & CPU_BASED_USE_IO_BITMAPS) {
		__vmwrite(IO_BITMAP_A, page_phys_address(vcpu->io_bitmap_a));
		__vmwrite(IO_BITMAP_B, page_phys_address(vcpu->io_bitmap_b));
	}

	if (cpu_based_vm_exec_ctrl & CPU_BASED_USE_MSR_BITMAPS) {
		__vmwrite(MSR_BITMAP, page_phys_address(vcpu->msr_bitmap));
		__vmwrite(VM_EXIT_MSR_LOAD_ADDR, page_phys_address(vcpu->host_msr));
		__vmwrite(VM_ENTRY_MSR_LOAD_ADDR, page_phys_address(vcpu->guest_msr));
		__vmwrite(VM_EXIT_MSR_STORE_ADDR, page_phys_address(vcpu->guest_msr));
	}
	printk("cpu_based_vm_exec_ctrl:%llx\n", cpu_based_vm_exec_ctrl);
	__vmwrite(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_ctrl);

	cpu_based_vm_exec_ctrl2 = SECONDARY_EXEC_UNRESTRICTED_GUEST
		| SECONDARY_EXEC_RDTSCP
		| SECONDARY_EXEC_ENABLE_EPT
		| SECONDARY_EXEC_ENABLE_VPID
		| SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES
		| SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY
		| SECONDARY_EXEC_APIC_REGISTER_VIRT
		| SECONDARY_EXEC_SHADOW_VMCS
		| SECONDARY_EXEC_RDRAND_EXITING
		;
	if ((cpu_based_vm_exec_ctrl2 | vcpu->vmx_cap_msrs.cpu_based2_allow1_mask) != vcpu->vmx_cap_msrs.cpu_based2_allow1_mask) {
		printk("Warning:setting secondary_vm_exec_control:%llx unsupported.\n", 
			(cpu_based_vm_exec_ctrl2 & vcpu->vmx_cap_msrs.cpu_based2_allow1_mask) ^ cpu_based_vm_exec_ctrl2);
		cpu_based_vm_exec_ctrl2 |= vcpu->vmx_cap_msrs.cpu_based2_allow0_mask;
		cpu_based_vm_exec_ctrl2 &= vcpu->vmx_cap_msrs.cpu_based2_allow1_mask;
	}

	printk("cpu_based_vm_exec_ctrl2:%llx\n", cpu_based_vm_exec_ctrl2);
	__vmwrite(SECONDARY_VM_EXEC_CONTROL, cpu_based_vm_exec_ctrl2);
	if (cpu_based_vm_exec_ctrl2 & SECONDARY_EXEC_ENABLE_EPT) {
		__vmwrite(EPT_POINTER, page_phys_address(vcpu->eptp_base) | 0x5e);
	}

	if (cpu_based_vm_exec_ctrl2 & SECONDARY_EXEC_APIC_REGISTER_VIRT) {
		__vmwrite(VIRTUAL_APIC_PAGE_ADDR, page_phys_address(vcpu->vapic_page));
	}

	if (cpu_based_vm_exec_ctrl2 & SECONDARY_EXEC_SHADOW_VMCS) {
		vcpu->shadow_vmcs_enabled = true;
		__vmwrite(VMREAD_BITMAP, page_phys_address(vcpu->vmread_bitmap));
		__vmwrite(VMWRITE_BITMAP, page_phys_address(vcpu->vmwrite_bitmap));
	}

	vm_entry_ctrl = VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR
		//| VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL
		| VM_ENTRY_LOAD_IA32_EFER;

	if (vcpu->guest_state.ia32_efer & 0x500)
		vm_entry_ctrl |= VM_ENTRY_IA32E_MODE;

	if ((vm_entry_ctrl | vcpu->vmx_cap_msrs.vm_entry_allow1_mask) != vcpu->vmx_cap_msrs.vm_entry_allow1_mask) {
		printk("Warning:setting vm_entry_controls:%llx unsupported.\n", 
			(vm_entry_ctrl & vcpu->vmx_cap_msrs.vm_entry_allow1_mask) ^ vm_entry_ctrl);
		vm_entry_ctrl |= vcpu->vmx_cap_msrs.vm_entry_allow0_mask;
		vm_entry_ctrl &= vcpu->vmx_cap_msrs.vm_entry_allow1_mask;
	}

	printk("vm_entry_ctrl:%llx\n", vm_entry_ctrl);
	__vmwrite(VM_ENTRY_CONTROLS, vm_entry_ctrl);

	vm_exit_ctrl = VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR
		| VM_EXIT_SAVE_IA32_EFER
		| VM_EXIT_LOAD_IA32_EFER
		| VM_EXIT_ACK_INTR_ON_EXIT
		| VM_EXIT_HOST_ADDR_SPACE_SIZE
		//| VM_EXIT_SAVE_VMX_PREEMPTION_TIMER
		;
	if ((vm_exit_ctrl | vcpu->vmx_cap_msrs.vm_exit_allow1_mask) != vcpu->vmx_cap_msrs.vm_exit_allow1_mask) {
		printk("Warning:setting vm_exit_controls:%llx unsupported.\n", 
			(vm_exit_ctrl & vcpu->vmx_cap_msrs.vm_exit_allow1_mask) ^ vm_exit_ctrl);
		vm_exit_ctrl |= vcpu->vmx_cap_msrs.vm_exit_allow0_mask;
		vm_exit_ctrl &= vcpu->vmx_cap_msrs.vm_exit_allow1_mask;
	}

	printk("vm_exit_ctrl:%llx\n", vm_exit_ctrl);
	__vmwrite(VM_EXIT_CONTROLS, vm_exit_ctrl);
	__vmwrite(CR3_TARGET_COUNT, 0);
	__vmwrite(CR0_GUEST_HOST_MASK,
		vcpu->vmx_cap_msrs.vmx_cr0_fixed0 & vcpu->vmx_cap_msrs.vmx_cr0_fixed1 & 0xfffffffe);
	__vmwrite(CR4_GUEST_HOST_MASK,
		vcpu->vmx_cap_msrs.vmx_cr4_fixed0 & vcpu->vmx_cap_msrs.vmx_cr4_fixed1);
	__vmwrite(EXCEPTION_BITMAP, 0xffffffff);
}

void vmx_realmode_guest_init(struct vmx_vcpu *vcpu)
{
	vcpu->guest_state.cs.selector = 0;
	vcpu->guest_state.cs.base = 0;
	vcpu->guest_state.cs.limit = 0xffff;
	vcpu->guest_state.cs.ar_bytes = VMX_AR_P_MASK 
		| VMX_AR_TYPE_READABLE_CODE_MASK 
		| VMX_AR_TYPE_CODE_MASK 
		| VMX_AR_TYPE_ACCESSES_MASK 
		| VMX_AR_S_MASK;

	vcpu->guest_state.ds.selector = 0;
	vcpu->guest_state.ds.base = 0;
	vcpu->guest_state.ds.limit = 0xffff;
	vcpu->guest_state.ds.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.es.selector = 0;
	vcpu->guest_state.es.base = 0;
	vcpu->guest_state.es.limit = 0xffff;
	vcpu->guest_state.es.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.fs.selector = 0;
	vcpu->guest_state.fs.base = 0;
	vcpu->guest_state.fs.limit = 0xffff;
	vcpu->guest_state.fs.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.gs.selector = 0;
	vcpu->guest_state.gs.base = 0;
	vcpu->guest_state.gs.limit = 0xffff;
	vcpu->guest_state.gs.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.ss.selector = 0;
	vcpu->guest_state.ss.base = 0;
	vcpu->guest_state.ss.limit = 0xffff;
	vcpu->guest_state.ss.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.tr.selector = 0;
	vcpu->guest_state.tr.base = 0;
	vcpu->guest_state.tr.limit = 0xffff;
	vcpu->guest_state.tr.ar_bytes = VMX_AR_P_MASK | VMX_AR_TYPE_BUSY_16_TSS;

	vcpu->guest_state.ldtr.selector = 0;
	vcpu->guest_state.ldtr.base = 0;
	vcpu->guest_state.ldtr.limit = 0xffff;
	vcpu->guest_state.ldtr.ar_bytes = VMX_AR_UNUSABLE_MASK;

	vcpu->guest_state.gdtr.base = 0;
	vcpu->guest_state.gdtr.limit = 0xffff;
	vcpu->guest_state.idtr.base = 0;
	vcpu->guest_state.idtr.limit = 0xffff;
	
	vcpu->guest_state.ctrl_regs.cr0 = 
		vcpu->vmx_cap_msrs.vmx_cr0_fixed0 & vcpu->vmx_cap_msrs.vmx_cr0_fixed1 & 0x7ffffffe;
	vcpu->guest_state.ctrl_regs.cr2 = 0;
	vcpu->guest_state.ctrl_regs.cr3 = 0;
	vcpu->guest_state.ctrl_regs.cr4 = 
		vcpu->vmx_cap_msrs.vmx_cr4_fixed0 & vcpu->vmx_cap_msrs.vmx_cr4_fixed1;

	vcpu->guest_state.cr0_read_shadow = vcpu->guest_state.ctrl_regs.cr0;
	vcpu->guest_state.cr4_read_shadow = vcpu->guest_state.ctrl_regs.cr4;

	vcpu->guest_state.pdpte0 = 0;
	vcpu->guest_state.pdpte1 = 0;
	vcpu->guest_state.pdpte2 = 0;
	vcpu->guest_state.pdpte3 = 0;

	vcpu->guest_state.rip = 0x7c00;
	vcpu->guest_state.rflags = 0x2;
	memset(&vcpu->guest_state.gr_regs, 0, sizeof(struct general_regs));
	vcpu->guest_state.ia32_efer = 0;
}

void vmx_comptmode_guest_init(struct vmx_vcpu *vcpu)
{
	vcpu->guest_state.cs.selector = 0x10;
	vcpu->guest_state.cs.base = 0;
	vcpu->guest_state.cs.limit = 0xffff;
	vcpu->guest_state.cs.ar_bytes = VMX_AR_P_MASK 
		| VMX_AR_TYPE_READABLE_CODE_MASK 
		| VMX_AR_TYPE_CODE_MASK 
		| VMX_AR_TYPE_ACCESSES_MASK 
		| VMX_AR_S_MASK;

	vcpu->guest_state.ds.selector = 0;
	vcpu->guest_state.ds.base = 0;
	vcpu->guest_state.ds.limit = 0xffff;
	vcpu->guest_state.ds.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.es.selector = 0;
	vcpu->guest_state.es.base = 0;
	vcpu->guest_state.es.limit = 0xffff;
	vcpu->guest_state.es.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.fs.selector = 0;
	vcpu->guest_state.fs.base = 0;
	vcpu->guest_state.fs.limit = 0xffff;
	vcpu->guest_state.fs.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.gs.selector = 0;
	vcpu->guest_state.gs.base = 0;
	vcpu->guest_state.gs.limit = 0xffff;
	vcpu->guest_state.gs.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.ss.selector = 0;
	vcpu->guest_state.ss.base = 0;
	vcpu->guest_state.ss.limit = 0xffff;
	vcpu->guest_state.ss.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.tr.selector = 0;
	vcpu->guest_state.tr.base = 0;
	vcpu->guest_state.tr.limit = 0xffff;
	vcpu->guest_state.tr.ar_bytes = VMX_AR_P_MASK | VMX_AR_TYPE_BUSY_64_TSS;

	vcpu->guest_state.ldtr.selector = 0;
	vcpu->guest_state.ldtr.base = 0;
	vcpu->guest_state.ldtr.limit = 0xffff;
	vcpu->guest_state.ldtr.ar_bytes = VMX_AR_UNUSABLE_MASK;

	vcpu->guest_state.gdtr.base = 0;
	vcpu->guest_state.gdtr.limit = 0xffff;
	vcpu->guest_state.idtr.base = 0;
	vcpu->guest_state.idtr.limit = 0xffff;
	
	vcpu->guest_state.ctrl_regs.cr0 = 
		vcpu->vmx_cap_msrs.vmx_cr0_fixed0 & vcpu->vmx_cap_msrs.vmx_cr0_fixed1 & 0x7ffffffe;
	vcpu->guest_state.ctrl_regs.cr2 = 0;
	vcpu->guest_state.ctrl_regs.cr3 = 0;
	vcpu->guest_state.ctrl_regs.cr4 = 
		vcpu->vmx_cap_msrs.vmx_cr4_fixed0 & vcpu->vmx_cap_msrs.vmx_cr4_fixed1;

	vcpu->guest_state.cr0_read_shadow = vcpu->guest_state.ctrl_regs.cr0;
	vcpu->guest_state.cr4_read_shadow = vcpu->guest_state.ctrl_regs.cr4;

	vcpu->guest_state.pdpte0 = 0;
	vcpu->guest_state.pdpte1 = 0;
	vcpu->guest_state.pdpte2 = 0;
	vcpu->guest_state.pdpte3 = 0;

	vcpu->guest_state.rip = 0x7c9f;
	vcpu->guest_state.rflags = 0x2;
	memset(&vcpu->guest_state.gr_regs, 0, sizeof(struct general_regs));
	vcpu->guest_state.ia32_efer = 0;
}

void vmx_longmode_guest_init(struct vmx_vcpu *vcpu)
{
	vcpu->guest_state.cs.selector = 0;
	vcpu->guest_state.cs.base = 0;
	vcpu->guest_state.cs.limit = 0xffff;
	vcpu->guest_state.cs.ar_bytes = VMX_AR_P_MASK 
		| VMX_AR_TYPE_READABLE_CODE_MASK 
		| VMX_AR_TYPE_CODE_MASK 
		| VMX_AR_TYPE_ACCESSES_MASK 
		| VMX_AR_S_MASK;

	vcpu->guest_state.ds.selector = 0;
	vcpu->guest_state.ds.base = 0;
	vcpu->guest_state.ds.limit = 0xffff;
	vcpu->guest_state.ds.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.es.selector = 0;
	vcpu->guest_state.es.base = 0;
	vcpu->guest_state.es.limit = 0xffff;
	vcpu->guest_state.es.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.fs.selector = 0;
	vcpu->guest_state.fs.base = 0;
	vcpu->guest_state.fs.limit = 0xffff;
	vcpu->guest_state.fs.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.gs.selector = 0;
	vcpu->guest_state.gs.base = 0;
	vcpu->guest_state.gs.limit = 0xffff;
	vcpu->guest_state.gs.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.ss.selector = 0;
	vcpu->guest_state.ss.base = 0;
	vcpu->guest_state.ss.limit = 0xffff;
	vcpu->guest_state.ss.ar_bytes = VMX_AR_P_MASK
		| VMX_AR_TYPE_WRITABLE_DATA_MASK
		| VMX_AR_TYPE_ACCESSES_MASK
		| VMX_AR_S_MASK;

	vcpu->guest_state.tr.selector = 0;
	vcpu->guest_state.tr.base = 0;
	vcpu->guest_state.tr.limit = 0xffff;
	vcpu->guest_state.tr.ar_bytes = VMX_AR_P_MASK | VMX_AR_TYPE_BUSY_64_TSS;

	vcpu->guest_state.ldtr.selector = 0;
	vcpu->guest_state.ldtr.base = 0;
	vcpu->guest_state.ldtr.limit = 0xffff;
	vcpu->guest_state.ldtr.ar_bytes = VMX_AR_UNUSABLE_MASK;

	vcpu->guest_state.gdtr.base = 0;
	vcpu->guest_state.gdtr.limit = 0xffff;
	vcpu->guest_state.idtr.base = 0;
	vcpu->guest_state.idtr.limit = 0xffff;
	
	vcpu->guest_state.ctrl_regs.cr0 = ((X86_CR0_PE | X86_CR0_PG) |
		vcpu->vmx_cap_msrs.vmx_cr0_fixed0) & vcpu->vmx_cap_msrs.vmx_cr0_fixed1;
	vcpu->guest_state.ctrl_regs.cr2 = 0;
	vcpu->guest_state.ctrl_regs.cr3 = 0x10000;
	vcpu->guest_state.ctrl_regs.cr4 = (X86_CR4_PAE |
		vcpu->vmx_cap_msrs.vmx_cr4_fixed0) & vcpu->vmx_cap_msrs.vmx_cr4_fixed1;

	vcpu->guest_state.cr0_read_shadow = vcpu->guest_state.ctrl_regs.cr0;
	vcpu->guest_state.cr4_read_shadow = vcpu->guest_state.ctrl_regs.cr4;

	vcpu->guest_state.pdpte0 = 0;
	vcpu->guest_state.pdpte1 = 0;
	vcpu->guest_state.pdpte2 = 0;
	vcpu->guest_state.pdpte3 = 0;

	vcpu->guest_state.rip = 0x7cf9;
	vcpu->guest_state.rflags = 0x2;
	memset(&vcpu->guest_state.gr_regs, 0, sizeof(struct general_regs));
	vcpu->guest_state.ia32_efer = 0x500;
}

static void load_guest_state(struct vmx_vcpu *vcpu)
{
	__vmwrite(GUEST_CR0, vcpu->guest_state.ctrl_regs.cr0);
	__vmwrite(CR0_READ_SHADOW, vcpu->guest_state.cr0_read_shadow);
	__vmwrite(GUEST_CR3, vcpu->guest_state.ctrl_regs.cr3);
	__vmwrite(GUEST_CR4, vcpu->guest_state.ctrl_regs.cr4);
	__vmwrite(CR4_READ_SHADOW, vcpu->guest_state.cr4_read_shadow);

	__vmwrite(GUEST_RIP, vcpu->guest_state.rip);
	__vmwrite(GUEST_RFLAGS, vcpu->guest_state.rflags);
	
	__vmwrite(GUEST_RSP, vcpu->guest_state.gr_regs.rsp);
	__vmwrite(GUEST_DR7, 0);
	__vmwrite(GUEST_IA32_DEBUGCTL, 0);

	__vmwrite(GUEST_CS_SELECTOR, vcpu->guest_state.cs.selector);
	__vmwrite(GUEST_CS_BASE, vcpu->guest_state.cs.base);
	__vmwrite(GUEST_CS_LIMIT, vcpu->guest_state.cs.limit);
	__vmwrite(GUEST_CS_AR_BYTES, vcpu->guest_state.cs.ar_bytes);

	__vmwrite(GUEST_DS_SELECTOR, vcpu->guest_state.ds.selector);
	__vmwrite(GUEST_DS_BASE, vcpu->guest_state.ds.base);
	__vmwrite(GUEST_DS_LIMIT, vcpu->guest_state.ds.limit);
	__vmwrite(GUEST_DS_AR_BYTES, vcpu->guest_state.ds.ar_bytes);

	__vmwrite(GUEST_ES_SELECTOR, vcpu->guest_state.es.selector);
	__vmwrite(GUEST_ES_BASE, vcpu->guest_state.es.base);
	__vmwrite(GUEST_ES_LIMIT, vcpu->guest_state.es.limit);
	__vmwrite(GUEST_ES_AR_BYTES, vcpu->guest_state.es.ar_bytes);

	__vmwrite(GUEST_FS_SELECTOR, vcpu->guest_state.fs.selector);
	__vmwrite(GUEST_FS_BASE, vcpu->guest_state.fs.base);
	__vmwrite(GUEST_FS_LIMIT, vcpu->guest_state.fs.limit);
	__vmwrite(GUEST_FS_AR_BYTES, vcpu->guest_state.fs.ar_bytes);

	__vmwrite(GUEST_GS_SELECTOR, vcpu->guest_state.gs.selector);
	__vmwrite(GUEST_GS_BASE, vcpu->guest_state.gs.base);
	__vmwrite(GUEST_GS_LIMIT, vcpu->guest_state.gs.limit);
	__vmwrite(GUEST_GS_AR_BYTES, vcpu->guest_state.gs.ar_bytes);

	__vmwrite(GUEST_SS_SELECTOR, vcpu->guest_state.ss.selector);
	__vmwrite(GUEST_SS_BASE, vcpu->guest_state.ss.base);
	__vmwrite(GUEST_SS_LIMIT, vcpu->guest_state.ss.limit);
	__vmwrite(GUEST_SS_AR_BYTES, vcpu->guest_state.ss.ar_bytes);	

	__vmwrite(GUEST_TR_SELECTOR, vcpu->guest_state.tr.selector);
	__vmwrite(GUEST_TR_BASE, vcpu->guest_state.tr.base);
	__vmwrite(GUEST_TR_LIMIT, vcpu->guest_state.tr.limit);
	__vmwrite(GUEST_TR_AR_BYTES, vcpu->guest_state.tr.ar_bytes);
	
	__vmwrite(GUEST_LDTR_SELECTOR, vcpu->guest_state.ldtr.selector);
	__vmwrite(GUEST_LDTR_BASE, vcpu->guest_state.ldtr.base);
	__vmwrite(GUEST_LDTR_LIMIT, vcpu->guest_state.ldtr.limit);
	__vmwrite(GUEST_LDTR_AR_BYTES, vcpu->guest_state.ldtr.ar_bytes);

	__vmwrite(GUEST_GDTR_BASE, vcpu->guest_state.gdtr.base);
	__vmwrite(GUEST_GDTR_LIMIT, vcpu->guest_state.gdtr.limit);
	__vmwrite(GUEST_IDTR_BASE, vcpu->guest_state.idtr.base);
	__vmwrite(GUEST_IDTR_LIMIT, vcpu->guest_state.idtr.limit);

	__vmwrite(GUEST_SYSENTER_ESP, 0);
	__vmwrite(GUEST_SYSENTER_EIP, 0);
	__vmwrite(GUEST_SYSENTER_CS, 0);
	__vmwrite(GUEST_IA32_DEBUGCTL, 0);
	__vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL, 0);
	__vmwrite(GUEST_IA32_EFER, vcpu->guest_state.ia32_efer);
	__vmwrite(GUEST_IA32_PAT, 0);
	
	__vmwrite(GUEST_ACTIVITY_STATE, 0);

	__vmwrite(GUEST_PDPTR0, vcpu->guest_state.pdpte0);
	__vmwrite(GUEST_PDPTR1, vcpu->guest_state.pdpte1);
	__vmwrite(GUEST_PDPTR2, vcpu->guest_state.pdpte2);
	__vmwrite(GUEST_PDPTR3, vcpu->guest_state.pdpte3);

	__vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
	__vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	__vmwrite(GUEST_BNDCFGS, 0);

	__vmwrite(VMCS_LINK_POINTER, 0xffffffffffffffff);
	__vmwrite(APIC_ACCESS_ADDR, 0xfee00000);
}

void vm_exit_point(void);
static void vmx_prepare_switch_to_guest(struct vmx_vcpu *vcpu)
{
	struct desc_ptr dt;
	void *gdt;
	u32 msr_l, msr_h;
	unsigned long tmpl;
	u64 efer;
	u16 selector;

	__vmwrite(HOST_CR0, read_cr0());
	__vmwrite(HOST_CR3, read_cr3());
	__vmwrite(HOST_CR4, read_cr4());
	__vmwrite(HOST_CS_SELECTOR, __KERNEL_CS);

	savesegment(ds, selector);
	__vmwrite(HOST_DS_SELECTOR, selector);
	savesegment(es, selector);
	__vmwrite(HOST_ES_SELECTOR, selector);

	savesegment(fs, selector);
	__vmwrite(HOST_FS_SELECTOR, selector);
	savesegment(gs, selector);
	__vmwrite(HOST_GS_SELECTOR, selector);
	__vmwrite(HOST_SS_SELECTOR, __KERNEL_DS);
	__vmwrite(HOST_TR_SELECTOR, GDT_ENTRY_TSS * 8);
	rdmsrl(MSR_FS_BASE, tmpl);
	__vmwrite(HOST_FS_BASE, tmpl);
	rdmsrl(MSR_GS_BASE, tmpl);
	__vmwrite(HOST_GS_BASE, tmpl);

	gdt = get_current_gdt_ro();
	__vmwrite(HOST_GDTR_BASE, (long)gdt);
	store_idt(&dt);
	__vmwrite(HOST_IDTR_BASE, dt.address);

	vcpu->host_state.ldt = kvm_read_ldt();

	__vmwrite(HOST_TR_BASE, kvm_read_tr_base());

	__vmwrite(HOST_RIP, (long)vm_exit_point);
	
	rdmsr(MSR_IA32_SYSENTER_CS, msr_l, msr_h);
	__vmwrite(HOST_IA32_SYSENTER_CS, msr_l);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	__vmwrite(HOST_IA32_SYSENTER_EIP, tmpl);
	rdmsrl(MSR_IA32_SYSENTER_ESP, tmpl);
	__vmwrite(HOST_IA32_SYSENTER_ESP, tmpl);

	rdmsrl(MSR_IA32_CR_PAT, tmpl);
	__vmwrite(HOST_IA32_PAT, tmpl);
	rdmsrl(MSR_EFER, efer);
	__vmwrite(HOST_IA32_EFER, efer);

	rdmsrl(MSR_IA32_PERF_CTL, tmpl);
	__vmwrite(HOST_IA32_PERF_GLOBAL_CTRL, tmpl);
}

static int vmx_enter_longmode(struct vmx_vcpu *vcpu)
{
	u64 efer = __vmread(GUEST_IA32_EFER);
	u64 cr0 = __vmread(GUEST_CR0);
	u64 cr4 = __vmread(GUEST_CR4);
	__vmwrite(GUEST_CR0, cr0 | X86_CR0_PE | X86_CR0_PG);
	__vmwrite(GUEST_CR4, cr4 | X86_CR4_PAE);
	__vmwrite(GUEST_TR_AR_BYTES, VMX_AR_P_MASK | VMX_AR_TYPE_BUSY_64_TSS);
	__vmwrite(VM_ENTRY_CONTROLS,
		__vmread(VM_ENTRY_CONTROLS) | VM_ENTRY_IA32E_MODE
		);
	__vmwrite(GUEST_IA32_EFER, efer | 0x500);
	printk("vmx:enter long mode.\n");
	return 0;
}

int vmx_handle_cr_access(struct vmx_vcpu *vcpu)
{
	u32 exit_qualification = __vmread(EXIT_QUALIFICATION);
	int access_type = (exit_qualification >> 4) & 0x3;
	int cr = exit_qualification & 0xf;
	int reg = (exit_qualification >> 8) & 0xf;
	u64 val = 0;
	switch(reg) {
		case 0:
			val = vcpu->guest_state.gr_regs.rax;
			break;
		case 1:
			val = vcpu->guest_state.gr_regs.rcx;
			break;
		case 2:
			val = vcpu->guest_state.gr_regs.rdx;
			break;
		case 3:
			val = vcpu->guest_state.gr_regs.rbx;
			break;
		case 4:
			val = vcpu->guest_state.gr_regs.rsp;
			break;
		case 5:
			val = vcpu->guest_state.gr_regs.rbp;
			break;
		case 6:
			val = vcpu->guest_state.gr_regs.rsi;
			break;
		case 7:
			val = vcpu->guest_state.gr_regs.rdi;
			break;
		case 8:
			val = vcpu->guest_state.gr_regs.r8;
			break;
		case 9:
			val = vcpu->guest_state.gr_regs.r9;
			break;
		case 10:
			val = vcpu->guest_state.gr_regs.r10;
			break;
		case 11:
			val = vcpu->guest_state.gr_regs.r11;
			break;
		case 12:
			val = vcpu->guest_state.gr_regs.r12;
			break;
		case 13:
			val = vcpu->guest_state.gr_regs.r13;
			break;
		case 14:
			val = vcpu->guest_state.gr_regs.r14;
			break;
		case 15:
			val = vcpu->guest_state.gr_regs.r15;
			break;		
	}
	printk("VM-Exit.CR%d %s, val = 0x%llx RIP = 0x%llx.\n",
		cr,
		access_type ? "read" : "write",
		val,
		vcpu->guest_state.rip
	);

	if (cr == 0) {
		vcpu->guest_state.cr0_read_shadow = val;
		__vmwrite(CR0_READ_SHADOW, vcpu->guest_state.cr0_read_shadow);
		if ((val & X86_CR0_PG) && (__vmread(GUEST_IA32_EFER) & (1 << 8))) {
			vmx_enter_longmode(vcpu);
		}
	}

	if (cr == 3) {
		__vmwrite(GUEST_CR3, val);
	}

	if (cr == 4) {
		vcpu->guest_state.cr4_read_shadow = val;
		__vmwrite(CR4_READ_SHADOW, vcpu->guest_state.cr0_read_shadow);
	}
	vcpu->guest_state.rip += __vmread(VM_EXIT_INSTRUCTION_LEN);
	return 0;
}
int vmx_handle_io(struct vmx_vcpu *vcpu)
{
	u64 exit_qualification = __vmread(EXIT_QUALIFICATION);
	u64 port = (exit_qualification >> 16) & 0xffff;
	bool direction = exit_qualification & (1 << 3);
	vcpu->guest_state.rip += __vmread(VM_EXIT_INSTRUCTION_LEN);
	printk("VM-Exit:I/O %s.RIP = 0x%llx Port = 0x%llx, val = 0x%llx\n",
		direction ? "write" : "read",
		vcpu->guest_state.rip,
		port,
		vcpu->guest_state.gr_regs.rax
	);

	return 0;
}

int vmx_handle_halt(struct vmx_vcpu *vcpu)
{
	printk("VM-Exit:Halt.RIP = 0x%llx\n", vcpu->guest_state.rip);
	return -1;
}

int vmx_handle_rdpmc(struct vmx_vcpu *vcpu)
{
	printk("VM-Exit:RDPMC.RIP = 0x%llx\n", vcpu->guest_state.rip);
	vcpu->guest_state.rip += __vmread(VM_EXIT_INSTRUCTION_LEN);
	return 0;
}

int vmx_handle_rdtsc(struct vmx_vcpu *vcpu)
{
	printk("VM-Exit:RDTSC.RIP = 0x%llx\n", vcpu->guest_state.rip);
	vcpu->guest_state.rip += __vmread(VM_EXIT_INSTRUCTION_LEN);
	return 0;
}

int vmx_handle_rdtscp(struct vmx_vcpu *vcpu)
{
	printk("VM-Exit:RDTSCP.RIP = 0x%llx\n", vcpu->guest_state.rip);
	vcpu->guest_state.rip += __vmread(VM_EXIT_INSTRUCTION_LEN);
	return 0;
}

int vmx_handle_rdrand(struct vmx_vcpu *vcpu)
{
	printk("VM-Exit:RDRAND.RIP = 0x%llx\n", vcpu->guest_state.rip);
	__vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0x80000020);
	//__vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	//printk("interrupt state:%llx\n", __vmread(GUEST_INTERRUPTIBILITY_INFO));
	vcpu->guest_state.rip += __vmread(VM_EXIT_INSTRUCTION_LEN);
	return 0;
}

int vmx_handle_rdseed(struct vmx_vcpu *vcpu)
{
	printk("VM-Exit:RDSEED.RIP = 0x%llx\n", vcpu->guest_state.rip);
	vcpu->guest_state.rip += __vmread(VM_EXIT_INSTRUCTION_LEN);
	return 0;
}

int vmx_handle_exception(struct vmx_vcpu *vcpu)
{
	u64 interruption_info = __vmread(VM_EXIT_INTR_INFO);
	u64 err_code = __vmread(VM_EXIT_INTR_ERROR_CODE);
	printk("VM-Exit:Guest exception (%lld) @ 0x%llx.type:%lld error code:%llx CR2 = 0x%llx\n", 
		interruption_info & 0xff,
		vcpu->guest_state.rip,
		(interruption_info >> 8) & 0x7,
		err_code,
		vcpu->guest_state.ctrl_regs.cr2);
	return -1;
}

void call_irq_soft(u64 vector)
{
	asm volatile(
		"soft_irq_call: \n\t"
			"subq $32, %0 \n\t"
			"movq %0, %%rax \n\t"
			"movq $14, %%rcx \n\t"
			"mulq %%rcx \n\t"
			"movabsq $soft_irq_table, %%rbx \n\t"
			"addq %%rbx, %%rax \n\t"
			"jmpq *%%rax \n\t"

		"soft_irq_table: \n\t"
		"index = 32 \n\t"
		".rept 0x100 - 0x20 \n\t"
			"int $(index) \n\t"
			"movabsq $soft_irq_end, %%rax \n\t"
			"jmpq *%%rax \n\t"
			"index = index + 1 \n\t"
		".endr \n\t"
		"soft_irq_end: \n\t"
			"nop \n\t"
		:
		:"r"(vector)
	);	
}

int vmx_handle_interrupt(struct vmx_vcpu *vcpu)
{
	u64 interruption_info = __vmread(VM_EXIT_INTR_INFO);
	u8 vector = interruption_info & 0xff;
	printk("VM-Exit:External Interrupt. vector = %x RIP = 0x%llx\n", vector, vcpu->guest_state.rip);
	call_irq_soft(vector);
	return 0;
}

static int handle_exit(struct vmx_vcpu *vcpu)
{
	int ret = 2;
	u32 exit_reason = __vmread(VM_EXIT_REASON);
	vcpu->guest_state.rip = __vmread(GUEST_RIP);
	if (exit_reason & 0x80000000) {
		printk("vm entry failed.reason = %x, exit_qualification = %llx, rip = %llx\n", 
			exit_reason, __vmread(EXIT_QUALIFICATION), vcpu->guest_state.rip);
	} else {
		switch (exit_reason) {
			case EXIT_REASON_EXCEPTION_NMI:
				ret = vmx_handle_exception(vcpu);
				break;
			case EXIT_REASON_EXTERNAL_INTERRUPT:
				ret = vmx_handle_interrupt(vcpu);
				break;
			case EXIT_REASON_TRIPLE_FAULT:
			case EXIT_REASON_PENDING_INTERRUPT:
			case EXIT_REASON_NMI_WINDOW:
			case EXIT_REASON_TASK_SWITCH:
			case EXIT_REASON_CPUID:
				break;
			case EXIT_REASON_HLT:
				ret = vmx_handle_halt(vcpu);
				break;
			case EXIT_REASON_INVD:
			case EXIT_REASON_INVLPG:
				break;
			case EXIT_REASON_RDPMC:
				ret = vmx_handle_rdpmc(vcpu);
				break;
			case EXIT_REASON_RDTSC:
				ret = vmx_handle_rdtsc(vcpu);
				break;
			case EXIT_REASON_VMCALL:
			case EXIT_REASON_VMCLEAR:
			case EXIT_REASON_VMLAUNCH:
			case EXIT_REASON_VMPTRLD:
			case EXIT_REASON_VMPTRST:
			case EXIT_REASON_VMREAD:
			case EXIT_REASON_VMRESUME:
			case EXIT_REASON_VMWRITE:
			case EXIT_REASON_VMOFF:
			case EXIT_REASON_VMON:
				break;
			case EXIT_REASON_CR_ACCESS:
				ret = vmx_handle_cr_access(vcpu);
				break;
			case EXIT_REASON_DR_ACCESS:
			case EXIT_REASON_IO_INSTRUCTION:
				ret = vmx_handle_io(vcpu);
				break;
			case EXIT_REASON_MSR_READ:
			case EXIT_REASON_MSR_WRITE:
				break;
			case EXIT_REASON_INVALID_STATE:
				printk("VM Exit:Invalid Guest State.\n");
				break;
			case EXIT_REASON_MSR_LOAD_FAIL:
			case EXIT_REASON_MWAIT_INSTRUCTION:
			case EXIT_REASON_MONITOR_TRAP_FLAG:
			case EXIT_REASON_MONITOR_INSTRUCTION:
			case EXIT_REASON_PAUSE_INSTRUCTION:
			case EXIT_REASON_MCE_DURING_VMENTRY:
			case EXIT_REASON_TPR_BELOW_THRESHOLD:
			case EXIT_REASON_APIC_ACCESS:
			case EXIT_REASON_EOI_INDUCED:
			case EXIT_REASON_GDTR_IDTR:
			case EXIT_REASON_LDTR_TR:
			case EXIT_REASON_EPT_VIOLATION:
			case EXIT_REASON_EPT_MISCONFIG:
			case EXIT_REASON_INVEPT:
				break;
			case EXIT_REASON_RDTSCP:
				ret = vmx_handle_rdtscp(vcpu);
				break;
			case EXIT_REASON_PREEMPTION_TIMER:
			case EXIT_REASON_INVVPID:
			case EXIT_REASON_WBINVD:
			case EXIT_REASON_XSETBV:
			case EXIT_REASON_APIC_WRITE:
				break;
			case EXIT_REASON_RDRAND:
				ret = vmx_handle_rdrand(vcpu);
				break;
			case EXIT_REASON_INVPCID:
			case EXIT_REASON_VMFUNC:
			case EXIT_REASON_ENCLS:
				break;
			case EXIT_REASON_RDSEED:
				ret = vmx_handle_rdseed(vcpu);
				break;
			case EXIT_REASON_PML_FULL:
			case EXIT_REASON_XSAVES:
			case EXIT_REASON_XRSTORS:
				break;
			default:
				printk("VM-Exit:Unhandled exit reason:%d\n", exit_reason & 0xff);
				break;
		}
		if (ret == 2) {
			printk("exit_reason:%d RIP = 0x%llx\n", exit_reason, vcpu->guest_state.rip);
			ret = 0;
		}
	}
	__vmwrite(GUEST_RIP, vcpu->guest_state.rip);
	return ret;
}

static int vmx_vcpu_run(struct vmx_vcpu *vcpu)
{
	int ret = 0;
	while (1) {
		ret = __vmx_vcpu_run(vcpu);
		if (ret != 0) {
			printk("vm entry failed. RIP = 0x%llx instruction error:%lld\n",
				vcpu->guest_state.rip,
				__vmread(VM_INSTRUCTION_ERROR)
			);
			break;
		}
		ret = handle_exit(vcpu);
		if (ret != 0)
			break;
	}
	return 0;
}

static int __init vmx_prober_init(void)
{
	int ret = 0;
	vcpu = kmalloc(sizeof(*vcpu), GFP_KERNEL);
	memset(vcpu, 0, sizeof(*vcpu));

	vmx_mem_alloc(vcpu);

	local_irq_disable();
	get_cpu();

	if (vmx_hardware_enable(vcpu)) {
		ret = -1;
		goto out;
	}

	vmx_msrs_detect(vcpu);
/*
	vmcs_layout_detect(vcpu, vmcs_16bit_ctrl_fields, ARRAY_SIZE(vmcs_16bit_ctrl_fields), 2);
	vmcs_layout_detect(vcpu, vmcs_16bit_guest_state_fields, ARRAY_SIZE(vmcs_16bit_guest_state_fields), 2);
	vmcs_layout_detect(vcpu, vmcs_16bit_host_state_fields, ARRAY_SIZE(vmcs_16bit_host_state_fields), 2);

	vmcs_layout_detect(vcpu, vmcs_64bit_ctrl_fields, ARRAY_SIZE(vmcs_64bit_ctrl_fields), 8);
	vmcs_layout_detect(vcpu, vmcs_64bit_readonly_fields, ARRAY_SIZE(vmcs_64bit_readonly_fields), 8);
	vmcs_layout_detect(vcpu, vmcs_64bit_guest_state_fields, ARRAY_SIZE(vmcs_64bit_guest_state_fields), 8);
	vmcs_layout_detect(vcpu, vmcs_64bit_host_state_fields, ARRAY_SIZE(vmcs_64bit_host_state_fields), 8);

	vmcs_layout_detect(vcpu, vmcs_32bit_ctrl_fields, ARRAY_SIZE(vmcs_32bit_ctrl_fields), 4);
	vmcs_layout_detect(vcpu, vmcs_32bit_readonly_fields, ARRAY_SIZE(vmcs_32bit_readonly_fields), 4);
	vmcs_layout_detect(vcpu, vmcs_32bit_guest_state_fields, ARRAY_SIZE(vmcs_32bit_guest_state_fields), 4);
	vmcs_layout_detect(vcpu, vmcs_32bit_host_state_field, ARRAY_SIZE(vmcs_32bit_host_state_field), 4);

	vmcs_layout_detect(vcpu, vmcs_natural_width_ctrl_fields, ARRAY_SIZE(vmcs_natural_width_ctrl_fields), 8);
	vmcs_layout_detect(vcpu, vmcs_natural_width_readonly_fields, ARRAY_SIZE(vmcs_natural_width_readonly_fields), 8);
	vmcs_layout_detect(vcpu, vmcs_natural_width_guest_state_fields, ARRAY_SIZE(vmcs_natural_width_guest_state_fields), 8);
	vmcs_layout_detect(vcpu, vmcs_natural_width_host_state_fields, ARRAY_SIZE(vmcs_natural_width_host_state_fields), 8);
*/
	vmx_realmode_guest_init(vcpu);
	//vmx_longmode_guest_init(vcpu);
	//vmx_comptmode_guest_init(vcpu);
	alloc_guest_memory(vcpu, 0, 8);
	copy_code_to_guest(vcpu);

	vmx_ctrl_setup(vcpu);
	__invept(VMX_EPT_EXTENT_GLOBAL, page_phys_address(vcpu->eptp_base), 0);
	vmx_prepare_switch_to_guest(vcpu);
	load_guest_state(vcpu);

	ret = vmx_vcpu_run(vcpu);
	printk("guest terminated.\n");

out:
	if (ret == -1) {
		vmx_hardware_disable(vcpu);
	}
	put_cpu();
	local_irq_enable();

	return ret;
}

static void __exit vmx_prober_exit(void)
{
	u64 vmcs_phys;
	vmcs_phys = page_to_pfn(vcpu->vmcs_pg) * PAGE_SIZE;
	smp_call_function_single(vcpu->cpu, vmx_hardware_disable, vcpu, 1);
	free_pages((long)page_address(vcpu->guest_state.guest_memory), vcpu->guest_state.guest_memory_order);
	free_ept_page(vcpu->eptp_base, 0);
	vmx_mem_free(vcpu);
	kfree(vcpu);
}

module_init(vmx_prober_init);
module_exit(vmx_prober_exit);
MODULE_LICENSE("GPL");
