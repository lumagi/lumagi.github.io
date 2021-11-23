---
layout: post
title:  "ABI issues when compiling kernel modules for packaged Kali kernels"
date:   2021-11-21 18:21:11 +0100
categories: linux kali
image: /assets/test.png
---
My company uses the ETAS ES582.1 CAN adapters to interface with a CAN bus. Since recently, the kernel has mainline support for these devices (the *etas_es58* driver). However, my work operating system of choice, Kali Linux, does not ship with a prebuilt kernel module for the devices out of the box. Hence, I needed to manually compile the module to use the devices under Linux. While doing so, I ran into binary compatibility issues and ended up debugging the module loading process with QEMU to figure out the root cause. This blog post is a summary of the short journey. I first explain the QEMU VM installation process, explain the issues I encountered, and outline the debugging process to pinpoint the issue.

On the host, I used an Arch Linux installation. The QEMU VM ran the target operating system, a Kali Linux installation. All my attempts were made on Kernel version *5.14.16*.

## Setting up a QEMU VM
On Arch, I merely needed to install the *qemu* package to get started. I then set up the VM image and started the installation. For the image, I intentionally used the *raw* format because on *ext4* it doesn't actually occupy any disk space until written to and because it can easily be mounted. I used a rather big image size to accommodate the source code and debug package. The second command starts up the VM with KVM, 4GB of memory and inserts the Kali installation disk.

{% highlight shell %}
$ qemu-img create -f raw kali_hd2.raw 16G
$ qemu-system-x86_64 -boot order=d -drive file=kali_hd.raw,format=raw -m 4G -enable-kvm -cdrom kali-linux-2021.3a-installer-netinst-amd64.iso
{% endhighlight %}

I installed a minimal Kali version without desktop environment and no preinstalled pentesting tools to reduce the size. Next, I ran the VM without ISO and with enabled gdb stub for attaching the debugger later on:

{% highlight shell %}
$ qemu-system-x86_64 -boot order=d -drive file=kali_hd.raw,format=raw -m 4G -enable-kvm -s
{% endhighlight %}

## Compiling the kernel module
The next step was to actually compile the module inside the VM. I used the *linux-source* package for maximum compatibility with the prebuilt kernel. apt automatically pulled in Kali package version *5.14.16-1kali1*.

{% highlight shell %}
$ sudo apt-get install build-essential libncurses5-dev libelf-dev libssl-dev
$ sudo apt-get install linux-source linux-headers-amd64
$ tar -xf /usr/src/linux-source-5.14.tar.xz
$ cd linux-source-5.14/
{% endhighlight %}

Next, I prepared the sources for compilation. I copied the configuration file and module symbol version file from the *linux-headers* package.
{% highlight shell %}
$ cp /usr/src/linux-headers-5.14.0-kali4-amd64/.config .
$ cp /usr/src/linux-headers-5.14.0-kali4-amd64/Module.symvers .
{% endhighlight %}

Since the module I wanted to compile was not enabled in the `.config` file, I manually enabled the module by adding the following line to the file:
{% highlight shell %}
CONFIG_CAN_ETAS_ES58X=m
{% endhighlight %}

Finally, I was able to compile the module. The first step in the series of commands checks the configuration file for completeness and queries the user for any missing configuration option. I stuck with the defaults.
{% highlight shell %}
$ make oldconfig
$ make prepare
$ make modules_prepare
$ make M=drivers/net/can/usb/etas_es58x/
{% endhighlight %}

Next I tried to `insmod` the new module and its dependencies for a quick test:
{% highlight shell %}
$ for i in can-dev usbcore crc16; do sudo modprobe $i; done
$ sudo insmod drivers/net/can/usb/etas_es58x/etas_es58x.ko
insmod: ERROR: could not insert module drivers/net/can/usb/etas_es58x/etas_es58x.ko: Invalid module format
{% endhighlight %}

So there seemed to be some issue with the module. Next, I checked the kernel log:
{% highlight shell %}
$ sudo dmesg | tail -n 1
[ 2056.862808] module: x86/modules: Skipping invalid relocation target, existing value is nonzero for type 1, loc 00000000909cc68f, val ffffffffc087f984
{% endhighlight %}

The debug message was rather cryptic, but there seemed to be some issue with the symbol relocation during module linking.

## Tracing the relocation error in kernel source code
From the debug message, I was able to trace the location in the code where the linking process failed. The message was printed from inside `__apply_relocate_add` in [arch/x86/kernel/module.c](https://github.com/torvalds/linux/blob/7d2a07b769330c34b4deabeed939325c77a7ec2f/arch/x86/kernel/module.c#L130). The function is responsible for applying relocations to an ELF section of the module.

### A short excursion on relocations
In generic terms, a relocation links the reference of a symbol to its definition. As an example, if a kernel module wants to call a function like `printk`, which it does not provide itself, it must know the address at which the function is located. Since the address is not known at compile time, it must be dynamically inserted into the module at load time. The process of performing this search and replace is defined by a relocation.

The relocations that need to be applied to the kernel module at startup are stored in the ELF file along with code and data. For each section to which relocations must be applied, the module contains a `.rela` section with relocations. As an example, most modules contain a `.text` section that in turn contains the compiled code of the module. The relocations for that section are stored in the `.rela.text` section.

Each relocation in a `.rela` section consists of several values:
* The location relative to the start of the target section at which the relocation must be applied.
* A link to the symbol that must be inserted at the specified location
* The type of the relocation. Relocation types are specific to a processor and define how the symbol value must be inserted at the location.
* (An addend, however this is not strictly relevant to this post)

To give a quick example, below I list a relocation from the `.rela.text` section in the *etas_es58x* module:
```
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000031  00c900000004 R_X86_64_PLT32    0000000000000000 memcpy - 4
```
The relocation specifies that the address of symbol `memcpy` must be placed at offset `0x31` relative to the beginning of the `.text` section.

### Understanding the relocation error
Below is the source code of `__apply_relocate_add` ([arch/x86/kernel/module.c](https://github.com/torvalds/linux/blob/7d2a07b769330c34b4deabeed939325c77a7ec2f/arch/x86/kernel/module.c#L130)). The function applies all relocations contained in a single `.rela` section. For each relocation, it calculates the absolute address of the relocation in `loc` and the symbol value in `val`. The switch case statement that follows is responsible for applying the symbol value according to the relocation type. The function also performs a sanity check before it applies a relocation: it checks if the location in memory is properly initialized to zero. If not, it aborts with an error message.

{% highlight C %}
static int __apply_relocate_add(Elf64_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me,
		   void *(*write)(void *dest, const void *src, size_t len))
{
	unsigned int i;
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
	Elf64_Sym *sym;
	void *loc;
	u64 val;

	DEBUGP("Applying relocate section %u to %u\n",
	       relsec, sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset;

		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf64_Sym *)sechdrs[symindex].sh_addr
			+ ELF64_R_SYM(rel[i].r_info);

		DEBUGP("type %d st_value %Lx r_addend %Lx loc %Lx\n",
		       (int)ELF64_R_TYPE(rel[i].r_info),
		       sym->st_value, rel[i].r_addend, (u64)loc);

		val = sym->st_value + rel[i].r_addend;

		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_64:
			if (*(u64 *)loc != 0)
				goto invalid_relocation;
			write(loc, &val, 8);
			break;
		case R_X86_64_32:
			if (*(u32 *)loc != 0)
				goto invalid_relocation;
			write(loc, &val, 4);
			if (val != *(u32 *)loc)
				goto overflow;
			break;
		case R_X86_64_32S:
			if (*(s32 *)loc != 0)
				goto invalid_relocation;
			write(loc, &val, 4);
			if ((s64)val != *(s32 *)loc)
				goto overflow;
			break;
		case R_X86_64_PC32:
		case R_X86_64_PLT32:
			if (*(u32 *)loc != 0)
				goto invalid_relocation;
			val -= (u64)loc;
			write(loc, &val, 4);
#if 0
			if ((s64)val != *(s32 *)loc)
				goto overflow;
#endif
			break;
		case R_X86_64_PC64:
			if (*(u64 *)loc != 0)
				goto invalid_relocation;
			val -= (u64)loc;
			write(loc, &val, 8);
			break;
		default:
			pr_err("%s: Unknown rela relocation: %llu\n",
			       me->name, ELF64_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
	return 0;

invalid_relocation:
	pr_err("x86/modules: Skipping invalid relocation target, existing value is nonzero for type %d, loc %p, val %Lx\n",
	       (int)ELF64_R_TYPE(rel[i].r_info), loc, val);
	return -ENOEXEC;

overflow:
	pr_err("overflow in relocation type %d val %Lx\n",
	       (int)ELF64_R_TYPE(rel[i].r_info), val);
	pr_err("`%s' likely not compiled with -mcmodel=kernel\n",
	       me->name);
	return -ENOEXEC;
}
{% endhighlight %}

This error message is the same as the one that was displayed when I tried to load my freshly-compiled module. Apparently, the dynamic linker encountered a relocation where the target address already held a non-zero value. However, a quick check with `readelf -a etas_es58x.ko` revealed that none of the relocation targets in the respective sections of the ELF file held a non-zero value. Consequently, the location had to have been manipulated at runtime while the module was being loaded. Unfortunately, the error message itself did not yield andy useful information, like the section in which the issue occurred or the name of the affected symbol. Hence, I decided to investigate the issue further by debugging the function at runtime using QEMU.

## Debugging the Kernel with QEMU and gdb
