---
title: "FireCracker internals: a deep dive inside the technology powering AWS Lambda"
layout: post
---

You are most likely familiar with AWS Lambda and Fargate — Amazon’s serverless computing engines. At its nature, serverless computing introduces quite a challenging task requiring both tight security and great performance. For exactly that matter Amazon came up with its microVM solution called **FireCracker**.

## Micro what?

MicroVMs are merely a fancy name for minimal, lightweight Virtual Machines. They are spawned by lightweight **Virtual Machine Monitors** (VMMs), stripped out of redundant & nice-to-have features. Much like good-old fashioned VMs, they provide hardware-level virtualization for isolation & security.

MicroVM in regard to this blog post is basically a virtualization technology which is tailor-made for container workloads.

## **Back to FireCracker**

FireCracker is a VMM which utilizes Linux Kernel-based Virtual Machine (KVM). It is created by Amazon to solve their container workloads needs. It is [open source](https://github.com/firecracker-microvm/firecracker), written in (the incredibly awesome) Rust, and used in production since 2018.

Up until recently, Lambda was being run on top of regular Linux containers isolated inside separate virtual machines. Each container served a different Lambda function while each VM served a different tenant. Although highly effective in terms of security, this set-up meant limited performance and has proven to be hard to pack variable-size workloads onto fixed-size VMs.

Amazon decided to come-up with a better solution for its serverless workloads requiring:

-   Consistent, close-to-native **performance**, which is also not being affected by other functions running on the same node
-   Functions must be strongly **isolated** and protected against information disclosure, privilege escalation, and other security risks
-   Full **compatibility** so functions are able to run arbitrary libraries and binaries without any re-compilation or code changes
-   High and flexible **scalability** allowing thousands of functions to run on a single machine
-   Functions must be able to **over-commit** resources, only using the minimal amount of resources they need
-   **Startup & tear-down** should be very quick so that functions’ cold-start times remain small

And so, it was successfully able to do so achieving impressing boot-times of “as little as 125ms” and supporting creation rates of “up to 150 microVMs per second per host” (source: [https://firecracker-microvm.github.io/](https://firecracker-microvm.github.io/)).

## Going deeper…

Each FireCracker process is bound to a single MicroVM and is composed of the following threads: an API Server, a VMM, and vCPU(s) threads — one per each guest CPU core.

FireCracker currently supports `x86_64` and `aarch64` architectures running kernel version 4.14 or later. Support for aarch64 is not feature complete yet and is considered an alpha stage release. All architecture-specific information in this post regards to the `x86_64` implementation.

### API Server

The API Server is the control plane of each FireCracker process. It is, per the [official docs](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md), “never in the fast path of the virtual machine”, and can be turned-off by passing the `no-api` flag given that a `config-file` is provided instead.

It is started by an `ApiServerAdapter` in a dedicated thread and exposes a REST API running on top of a unix socket. Endpoints exist for configuring guest kernel, boot arguments, net configuration, block device configuration, guest machine configuration and `cpuid`, logging, metrics, rate limiting, and the metadata service. Operations can be sent to the API server pre-boot and post-boost.

The communication between the API server thread and the VMM thread (discussed later) which runs & controls the actual VM is done using Rust channels.

Channels are notified about API requests arriving at the API server using an `epoll` event loop, which FC makes use of in various places to handle events:

```rust
// FD to notify of API events. This is a blocking eventfd by design.
// It is used in the config/pre-boot loop which is a simple blocking loop
// which only consumes API events.
let api_event_fd = EventFd::new(0).expect("Cannot create API Eventfd.");

// Channels for both directions between Vmm and Api threads.
let (to_vmm, from_api) = channel();
let (to_api, from_vmm) = channel();

thread::Builder::new()
      .name("fc_api".to_owned())
      .spawn(move || {
            match ApiServer::new(mmds_info, to_vmm, from_vmm, to_vmm_event_fd).bind_and_run(
                bind_path,
                process_time_reporter,
                &api_seccomp_filter,
              ) {
                   // ...
                  }
    }).expect("API thread spawn failed.");

```

Source: [firecracker/src/firecracker/src/api_server_adapter.rs](https://github.com/firecracker-microvm/firecracker/blob/1f697a61e1fde68e1abb2e2ef75f7bf9acbc3440/src/firecracker/src/api_server_adapter.rs#L119)

Once the API server is spawned, the `ApiServerAdapter` would go on and call `build_microvm_from_requests()` which loops using successive API calls, in order to pre-boot the VM:

```rust
 pub fn build_microvm_from_requests<F, G>(
        seccomp_filters: &BpfThreadMap,
        event_manager: &mut EventManager,
        instance_info: InstanceInfo,
        recv_req: F,
        respond: G,
        boot_timer_enabled: bool,
    ) -> result::Result<(VmResources, Arc<Mutex<Vmm>>), ExitCode>
    where
        F: Fn() -> VmmAction,
        G: Fn(ActionResult),
    {
        //...

        // Configure and start microVM through successive API calls.
        // Iterate through API calls to configure microVm.
        // The loop breaks when a microVM is successfully started, and a running Vmm is built.
        while preboot_controller.built_vmm.is_none() {
            // Get request, process it, send back the response.
            respond(preboot_controller.handle_preboot_request(recv_req()));
            // If any fatal errors were encountered, break the loop.
            if let Some(exit_code) = preboot_controller.fatal_error {
                return Err(exit_code);
            }
        }

        // ...
}

```

Source: [firecracker/src/vmm/src/rpc_interface.rs](https://github.com/firecracker-microvm/firecracker/blob/38524062228f5f6bf2d7a6e1ec227f362589b290/src/vmm/src/rpc_interface.rs#L252)

After successfully pre-booting the VM the `ApiServerAdapter` would run it calling `ApiServerAdapter::run_microvm()`.

> FC’s API Server specification can be found [here](https://github.com/firecracker-microvm/firecracker/blob/7edec888f8a4e496dffa55b75fab30836a122fad/src/api_server/swagger/firecracker.yaml)

### Boot Sequence and Linux Boot Protocol

A traditional PC boot sequence with a BIOS is consisted of the following steps:

Upon starting, the CPU  —  running in real mode  —  executes an instruction located at the hardware reset vector which jumps to a ROM location. That firmware code in turn loads the start-up program — BIOS in that case. The startup program executes a POST (power-on self test) integrity check to make sure that all hardware devices that it relies on are working properly.

Afterwards, it starts looking for a bootable device (CD drive, HDD, NIC) — failing to boot if none found. In case of an HDD, the bootable device would be the Master Boot Record (MBR) whose responsibility is to search for an active partition and execute its boot sector code. The boot sector code is basically the first-stage boot loader which is responsible for loading the kernel onto physical memory and transferring control to the OS.

Boot loader systems come in various forms. Different boot loaders implement a different number of stages, designed for dealing with various resource limitations, like the first-stage boot loader’s 512 bytes size limit. Grub, for instance, is a 3-layer boot loader.

However, the Linux Kernel does not necessarily require loading with a BIOS and a boot loader. Instead FireCracker takes advantage of the 64-bit Linux Boot Protocol, which specifies how the kernel image should be loaded and run. FC directly boots the Kernel at the `protected-mode` entry point rather than starting off from the 16-bit `real mode`.

As the official docs of the [Linux Boot Protocol](https://www.kernel.org/doc/Documentation/x86/boot.txt) state, the entry for the protected-mode is located at `0x100000`, as seen in the following schema:

```
For a modern bzImage kernel with boot protocol version >= 2.02, a
memory layout like the following is suggested:

    ~                        ~
        |  Protected-mode kernel |
100000  +------------------------+
    |  I/O memory hole     |
0A0000    +------------------------+
    |  Reserved for BIOS     |    Leave as much as possible unused
    ~                        ~
    |  Command line         |    (Can also be below the X+10000 mark)
X+10000    +------------------------+
    |  Stack/heap         |    For use by the kernel real-mode code.
X+08000    +------------------------+    
    |  Kernel setup         |    The kernel real-mode code.
    |  Kernel boot sector     |    The kernel legacy boot sector.
X       +------------------------+
    |  Boot loader         |    <- Boot sector entry point 0000:7C00
001000    +------------------------+
    |  Reserved for MBR/BIOS |
000800    +------------------------+
    |  Typically used by MBR |
000600    +------------------------+
    |  BIOS use only     |
000000    +------------------------+

... where the address X is as low as the design of the boot loader
permits.

```

Hence, FireCracker [sets](https://github.com/firecracker-microvm/firecracker/blob/a367796e66eeac42d9ce1294c0fbbca6191e9cf3/src/arch/src/x86_64/layout.rs#L19) `HIMEM_START` to `0x0010_0000` and ultimately passes it as the `start_address` when calling `load_kernel()`. `load_kernel()` in turn runs sanity checks against the provided image, reads in its segments, and finally returns the guest memory’s entry point.

```rust
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn load_kernel<F>(
    guest_mem: &GuestMemoryMmap,
    kernel_image: &mut F,
    start_address: u64,
) -> Result<GuestAddress>
where
    F: Read + Seek,
{
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelImage)?;
    let mut ehdr = elf::Elf64_Ehdr::default();
    ehdr.as_bytes()
        .read_from(0, kernel_image, mem::size_of::<elf::Elf64_Ehdr>())
        .map_err(|_| Error::ReadKernelDataStruct("Failed to read ELF header"))?;

    // Sanity checks
    // ...

    kernel_image
        .seek(SeekFrom::Start(ehdr.e_phoff))
        .map_err(|_| Error::SeekProgramHeader)?;
    let phdr_sz = mem::size_of::<elf::Elf64_Phdr>();
    let mut phdrs: Vec<elf::Elf64_Phdr> = vec![];
    for _ in 0usize..ehdr.e_phnum as usize {
        let mut phdr = elf::Elf64_Phdr::default();
        phdr.as_bytes()
            .read_from(0, kernel_image, phdr_sz)
            .map_err(|_| Error::ReadKernelDataStruct("Failed to read ELF program header"))?;
        phdrs.push(phdr);
    }

    // Read in each section pointed to by the program headers.
    for phdr in &phdrs {
        if (phdr.p_type & elf::PT_LOAD) == 0 || phdr.p_filesz == 0 {
            continue;
        }

        kernel_image
            .seek(SeekFrom::Start(phdr.p_offset))
            .map_err(|_| Error::SeekKernelStart)?;

        let mem_offset = GuestAddress(phdr.p_paddr);
        if mem_offset.raw_value() < start_address {
            return Err(Error::InvalidProgramHeaderAddress);
        }

        guest_mem
            .read_from(mem_offset, kernel_image, phdr.p_filesz as usize)
            .map_err(|_| Error::ReadKernelImage)?;
    }

    Ok(GuestAddress(ehdr.e_entry))
}

```

Source: [firecracker/src/kernel/src/loader/mod.rs](https://github.com/firecracker-microvm/firecracker/blob/1f697a61e1fde68e1abb2e2ef75f7bf9acbc3440/src/kernel/src/loader/mod.rs#L78)

FireCracker directly uses the uncompressed kernel image `vmlinux`, saving additional costs of going through the traditional boot sequence in which the kernel decompresses itself at startup. All of this special FC boot sequence described above enables a major performance boost ultimately resulting in what AWS Lambda customer experience as fast cold starts.

### Device model & VirtIO

Virtio is a device virtualization standard written by Rusty Russell (the same genius who wrote `iptables`!) as part of his work on the x86 Linux para-virtualization hypervisor `lguest`. As opposed to full virtualization - where the guest is agnostic to the fact that it’s being run on a different host - para-virtualization technology requires the guest to implement drivers on its own and cooperate with its host. This ultimately helps gaining better performance since the guest speaks directly to the host, instead of being mediated by traps & hardware emulation drivers. Obviously, this requires modifications in the guest OS in order for it to work. FireCracker is implemented using a para-virtualized KVM meaning better performance over a normal VM.

Think of it as the difference between talking to a foreigner directly in her/his native tongue (para-virtualization) vs talking to them with the help of a translator (full virtualization).

<p align="center">
  <img src="https://i.imgur.com/AupOnSz.png" alt="Full Virtualization vs Para-Virtualization" />
</p>

The purpose of Virtio is to offer an abstraction and a unified standard for the front-end drivers (on the guest), for the backend device drivers (on the host), and for the transport layer between the two ends.

The [specification](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html) lays out the requirements needed for implementing virtio-compatible systems. Front-end drivers are shipped out-of-the-box with Linux >= 2.6.25, while the backend drivers (hereinafter referred to as “devices”) must be implemented as per the docs.

Interaction between the guest and the host for the purpose of the accessing the data plane is based on a ring-buffer struct called `virtqueue` containing guest-allocated buffers. The host reads and writes to those guest memory regions. Each device can have more than one virtqueues, whereas each buffer can be either a read-only or a write-only - but not both. Each device holds a status field, feature bits, and configuration space in addition to the actual data written & read by that specific device.

Notifications between the two ends are used in order to notify the other end of:

1.  a configuration change (device -> driver)
2.  a used buffer by the device (device -> driver)
3.  an available buffer by the guest (driver -> device)

A good case for the better performance para-virtualization provides over full virtualization is Virtio’s ‘available buffer’ notifications mechanism which saves us a lot of costly VMExits. For instance, given NIC emulation on a full virtualization solution, there will be a VMExit for each byte being written to the emulated device. With virtio, the entire buffer will be written first and only then will a single VMExit be dispatched for the purpose of notifying the host of an available buffer.

Note that there’s an even better virtio backend implementation called vhost, which introduces in-kernel virtio devices for KVM featuring direct guest-kernel-to-host-kernel data plane, saving redundant host userspace to kernel space syscalls. FireCracker does not currently use this implementation. 

Virtio specifies 3 possible transport layers offering slightly different layouts & implementations of those drivers & devices:

1.  PCI Bus based transport
2.  Memory Mapped IO based transport (FC's chosen transport)
3.  Channel I/O based transport

One difference between PCI based transport and a MMIO one is that unlike PCI, MMIO provides no generic device discovery mechanism. This means that for each device the guest OS will need to know the location of the registers and interrupts used.

Generally, notifications from the guest to the host are just writes to a special register, which trigger a signal caught by the hypervisor (`ioeventfd` & VMExits), whilst notifications from the host to the guest are basic `irqfd` interruptions. Both ‘used buffer’ notifications & ‘available buffer’ notifications are suppressible since they can generally be very expensive operations. 

Back to FireCracker - each attached device (net, block, etc…) is being registered with its own MMIO transport instance, which is basically a struct implementing the [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002) specification + a `BusDevice` trait responding to reads or writes in an arbitrary address space.

When attaching a device, FC subscribes it to the general event loop. Each device is implementing a `MutEventSubscriber` trait which implements event handling for the device's `queue_evts` (that is, 'available buffer' notifications). Those queue events hold the index of the relevant `virtqueue` buffer, so for a balloon driver for example those could be `inflateq`, `deflateq`, and `statsq` queues.

FC registers each file descriptor in the device’s `queue_evts` (which are specific to that device) to be signaled by the **KVM itself** whenever address `0x050` (`virtio::NOTIFY_REG_OFFSET`) is written to inside the guest, using a `KVM_IOEVENTFD` ioctl. The `virtio::NOTIFY_REG_OFFSET` is called the Queue Notifier. As per the official MMIO spec "writing a value to this register notifies the device that there are new buffers to process in a queue". In the event of MMIO/PMIO guest addresses which are not registered using the `KVM_IOEVENTFD` ioctl, a write will trigger a regular VMexit.

> **KVM_IOEVENTFD**
> This ioctl attaches or detaches an ioeventfd to a legal pio/mmio address within the guest.  A guest write in the registered address will signal the provided event instead of triggering an exit.
[Link](https://www.kernel.org/doc/html/v5.10/virt/kvm/api.html#kvm-ioeventfd)

**Overall, the flow of registering a MMIO-based device is as follows:**

1.  FC allocates a new slot for the MMIO device
2.  It subscribes to the guest-triggered ioevents
3.  It registers an irqfd in order to be able to send interrupts to the guest
4.  Inserts the device at the MMIO slot
5.  And finally sets the kernel [bootparams](https://man7.org/linux/man-pages/man7/bootparam.7.html) to include the guest driver:
    
```rust
pub fn register_mmio_virtio_for_boot(  
    &mut self,  
    vm: &VmFd,  
    device_id: String,  
    mmio_device: MmioTransport,  
    _cmdline: &mut kernel_cmdline::Cmdline,  
    ) -> Result {  
            let mmio_slot = self.allocate_new_slot(1)?;  
            self.register_mmio_virtio(vm, device_id, mmio_device, &mmio_slot)?;  
            #[cfg(target_arch = “x86_64”)]  
            Self::add_virtio_device_to_cmdline(_cmdline, &mmio_slot)?;  
            Ok(mmio_slot)  
    }
```
Source: [firecracker/src/vmm/src/device_manager/mmio.rs](https://github.com/firecracker-microvm/firecracker/blob/1f697a61e1fde68e1abb2e2ef75f7bf9acbc3440/src/vmm/src/device_manager/mmio.rs#L238)

Being a minimal VMM, FC provides a rather limited set of emulated drivers: block storage (virtio-blk), network (virtio-net), vsock (virtio-vsock), balloon driver (virtio-balloon), a serial console, and a partial I8042 keyboard controller used only to stop the VM.

In addition to the above devices, FC guests also see both Programmable Interrupt Controllers (PICs) & the I/O Advanced Programmable Interrupt Controller (IOAPIC), and the KVM’s Programmable Interval Timer (PIT).

Legacy devices such as the serial console and the I8042 controller are based on Port Mapped IO. Each started `vcpu` is being set with a MMIO bus for the virtio devices and a PMIO bus for the legacy devices:  
```rust
pub fn start_vcpus(
        &mut self,
        mut vcpus: Vec<Vcpu>,
        vcpu_seccomp_filter: Arc<BpfProgram>,
    ) -> Result<()> {
        // ... redacted

        for mut vcpu in vcpus.drain(..) {
                vcpu.set_mmio_bus(self.mmio_device_manager.bus.clone());
                #[cfg(target_arch = "x86_64")]
                vcpu.kvm_vcpu
                    .set_pio_bus(self.pio_device_manager.io_bus.clone());

                // … redacted
        }

        // ... redacted
        
        Ok(())
}
```
Source: [firecracker/src/vmm/src/lib.rs](https://github.com/firecracker-microvm/firecracker/blob/6b4a4b1c0490e006e02db7579831cbf14e05abae/src/vmm/src/lib.rs#L276)

MMIO reads and writes trigger a VMExit which are handled, among other things, in a function named `run_emulation()` which runs the VCPU (will be discussed later on). Those VmExits are used for accessing the device’s control plane (i.e, its configuration space):
```rust
/// Runs the vCPU in KVM context and handles the kvm exit reason.
///
/// Returns error or enum specifying whether emulation was handled or interrupted.
pub fn run_emulation(&self) -> Result<VcpuEmulation> {
    match self.emulate() {
        VcpuExit::MmioRead(addr, data) => {
            if let Some(mmio_bus) = &self.kvm_vcpu.mmio_bus {
                mmio_bus.read(addr, data);
                METRICS.vcpu.exit_mmio_read.inc();
            }
            Ok(VcpuEmulation::Handled)
        }
        VcpuExit::MmioWrite(addr, data) => {
            if let Some(mmio_bus) = &self.kvm_vcpu.mmio_bus {
                mmio_bus.write(addr, data);
                METRICS.vcpu.exit_mmio_write.inc();
            }
            Ok(VcpuEmulation::Handled)
        }
        // ... redacted
        arch_specific_reason => {
            // run specific architecture emulation.
            self.kvm_vcpu.run_arch_emulation(arch_specific_reason)
        }
        // ... redacted
    }
}
```
Source: [firecracker/src/vmm/src/vstate/vcpu/mod.rs](https://github.com/firecracker-microvm/firecracker/blob/9a9f933775266c6c72a4a4400d78bfce43645409/src/vmm/src/vstate/vcpu/mod.rs#L455)


PMIO reads and writes are arch-specific and handled separately:
```rust
/// Runs the vCPU in KVM context and handles the kvm exit reason.
///
/// Returns error or enum specifying whether emulation was handled or interrupted.
pub fn run_arch_emulation(&self, exit: VcpuExit) -> super::Result<VcpuEmulation> {
    match exit {
        VcpuExit::IoIn(addr, data) => {
            if let Some(pio_bus) = &self.pio_bus {
                pio_bus.read(u64::from(addr), data);
                METRICS.vcpu.exit_io_in.inc();
            }
            Ok(VcpuEmulation::Handled)
        }
        VcpuExit::IoOut(addr, data) => {
            if let Some(pio_bus) = &self.pio_bus {
                pio_bus.write(u64::from(addr), data);
                METRICS.vcpu.exit_io_out.inc();
            }
            Ok(VcpuEmulation::Handled)
        }
    // ... redacted
}
```
Source: [firecracker/src/vmm/src/vstate/vcpu/x86_64.rs](https://github.com/firecracker-microvm/firecracker/blob/7edec888f8a4e496dffa55b75fab30836a122fad/src/vmm/src/vstate/vcpu/x86_64.rs#L397)

### Network

Guests’ network devices are backed by `tap` devices on the host:
```rust
impl Net {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(
        id: String,
        tap_if_name: String,
        guest_mac: Option<&MacAddr>,
        rx_rate_limiter: RateLimiter,
        tx_rate_limiter: RateLimiter,
        allow_mmds_requests: bool,
    ) -> Result<Self> {
        let tap = Tap::open_named(&tap_if_name).map_err(Error::TapOpen)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_gen::TUN_F_CSUM | net_gen::TUN_F_UFO | net_gen::TUN_F_TSO4 | net_gen::TUN_F_TSO6,
        )
        .map_err(Error::TapSetOffload)?;

        let vnet_hdr_size = vnet_hdr_len() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(Error::TapSetVnetHdrSize)?;

        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        // … redacted
    }
    
    // … redacted
}
```
Source: [firecracker/src/devices/src/virtio/net/device.rs](https://github.com/firecracker-microvm/firecracker/blob/9a9f933775266c6c72a4a4400d78bfce43645409/src/vmm/src/vstate/vcpu/mod.rs#L455)

### Vsock
Vsock was introduced as a method for a bi-directional host/guest communication. 
An alternative approach would be using virtio-console which provides such host/guest interaction but is rather limited. First of all, multiplexing N:1 connections over 1:1 serial ports is hard and ought to be handled at the application level. In addition, the API is based on a character device rather than on a sockets API and the semantics is stream semantics and does not fit well with datagram protocols. On top and above that, there is a quite small, hardcoded port limit on the host machine of around 512.

On the other end, Vsock offers regular unix domain sockets API (connect(), bind(), accept(), read(), write(), etc...) and therefore supports both datagram and stream semantics. There’s a dedicated address family called `AF_VSOCK` for that purpose. Source and destination addresses are made of tuples of 32-bit context ids (cid’s) and 32-bit ports in a host byte order.

FireCracker supports host-initiated vsock connections where the MicroVM must be started with a configured vsock driver. It also supports guest-initiated connections requiring the host to be listening on a destination port, sending a `VIRTIO_VSOCK_OP_RST` message to the guest otherwise.

### Storage

For storage FireCracker implements virtio-block devices backed by files on the host. It does not use a filesystem passthrough solution (virtio-fs) for the time being (perhaps due to security concerns?). Note that since there’s no hot-plug in FC, all of the VM’s block devices need to be attached prior to running the VM. In addition, in order to successfully mount such devices to the VM they should all be pre-formatted with a filesystem that the guest kernel supports.

All read and write operations are served using a single `requestq` virtio queue. Out of the official supported operations by the virtio specification:
```c
#define VIRTIO_BLK_T_IN           0
#define VIRTIO_BLK_T_OUT          1
#define VIRTIO_BLK_T_FLUSH        4
#define VIRTIO_BLK_T_DISCARD      11
#define VIRTIO_BLK_T_WRITE_ZEROES 13
```

FireCracker only supports IN, OUT, and FLUSH:
```rust
pub enum RequestType {
    In,
    Out,
    Flush,
    GetDeviceID,
    Unsupported(u32),
}
```

A rootfs block device must be configured prior to booting the VM, like so:
```bash
rootfs_path=$(pwd)"/your-rootfs.ext4"
curl --unix-socket /tmp/firecracker.socket -i \
  -X PUT 'http://localhost/drives/rootfs' \
  -H 'Accept: application/json'           \
  -H 'Content-Type: application/json'     \
  -d "{
        \"drive_id\": \"rootfs\",
        \"path_on_host\": \"${rootfs_path}\",
        \"is_root_device\": true,
        \"is_read_only\": false
   }"
```

An example for how to create a minimal rootfs image can be found at FireCracker’s [official docs](https://github.com/firecracker-microvm/firecracker/blob/7edec888f8a4e496dffa55b75fab30836a122fad/docs/rootfs-and-kernel-setup.md#creating-a-rootfs-image). 

### Ballooning
Ballooning is a concept which is meant to provide a solution for overcommitting memory. It allows for host-controlled, on-demand allocation and reclaiming of guest memory. 

A virtio-balloon device works so that the balloon guest driver allocates memory until reaching its target, specified by the host, and reports those new memory addresses back. Similarly the balloon driver frees memory back to the guest itself if it has more than the host device asks for. It is an independent “memory consumer/allocator” inside the guest kernel, which competes for memory with other processes, and operates within the pre-boot RAM limitations of the VM.

The host can remove balloon memory pages at will and hand them over to other guests. This enables the host to control and fine-tune each of its guests’ memory resources based on its own available resources, therefore enabling overcommitting.

<p align="center">
  <img src="https://i.imgur.com/i925RhD.png" alt="Ballooning" />
</p>

Virtio-balloon holds three virtio queues: `inflateq`, `deflateq`, and `statsq`.  Inflateq is used by the guest driver to report about addresses it has supplied to the host device (hence the “balloon” is inflated), while deflateq is used for reports of memory addresses used by the guest (hence the “balloon” is deflated). Statsq is optional and can be used by the guest to send out memory statistics. 

FireCracker’s implementation operates on a best-effort basis and works so that if a given VM fails to allocate additional memory pages, it prompts an error, sleeps for 200ms, and then attempts again

FC supports two of the three feature bits stated in the official virtio specification: 
1. `deflate_on_oom` (aka `VIRTIO_BALLOON_F_DEFLATE_ON_OOM`) - deflates memory from the balloon when processes which are not needed for kernel’s activities go OOM instead of killing them by OOM killer 
2. `stats_polling_interval_s` (aka `VIRTIO_BALLOON_F_STATS_VQ`) - specifies how often in seconds to send out statistics; disabled if set to 0.

The third (or first) feature bit, which FC doesn’t turn on, is `VIRTIO_BALLOON_F_MUST_TELL_HOST` meant for telling the driver that the host must be told before pages from the balloon are used.

Please note that the host must be monitored for any memory pressure on its own end and then operate the balloon accordingly. This is not a practical thing to do manually and should be dealt with automatically yet carefully.   

There a few security concerns and pitfalls requiring extra caring as documented in FC’s [FireCracker Ballooning documentation](https://github.com/firecracker-microvm/firecracker/blob/7edec888f8a4e496dffa55b75fab30836a122fad/docs/ballooning.md).

If you’re interested in the implementation of the guest balloon driver, which is pretty straight-forward, take a look [here](https://github.com/torvalds/linux/blob/master/drivers/virtio/virtio_balloon.c) and [here](https://github.com/torvalds/linux/blob/a48b0872e69428d3d02994dcfad3519f01def7fa/mm/balloon_compaction.c).

### IO Throttling

FireCracker provides I/O rate limiting for its virtio-net and virtio-block devices, allowing for both bandwidth (bytes/sec) and operations per second throttling. The implementation is based on token buckets, one per each rate-limiter type.

It is configurable via the api server and can be (optionally) configured per drive and per network interface. The configurable values are the refill time, the bucket size, and an optional one-time burst. 

See: [src/api_server/swagger/firecracker.yaml#L1086](https://github.com/firecracker-microvm/firecracker/blob/HEAD/src/api_server/swagger/firecracker.yaml#L1086)

### Legacy devices

As already mentioned, FireCracker emulates a few legacy devices on top of a PIO bus. For one, FireCracker emulates serial COM ports commonly seen on x86 as I/O ports `0x3f8`/`0x2f8`/`0x3e8`/`0x2e8`. More specifically it uses port `0x3f8` while `0x2f8`, `0x3e8`, and `0x2e8` are used as sinks connected nowhere. In addition, it also exposes an I8052 keyboard controller registered at port `0x060` and used by FC to control shutdowns and issue ctrl+alt+delete sequences used for that purpose.


```rust
pub fn register_devices(&mut self, vm_fd: &VmFd) -> Result<()> {
    self.io_bus
        .insert(self.stdio_serial.clone(), 0x3f8, 0x8)
        .map_err(Error::BusError)?;
    self.io_bus
        .insert(
            Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
            ))),
            0x2f8,
            0x8,
        )
        .map_err(Error::BusError)?;
    self.io_bus
        .insert(
            Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                self.com_evt_1_3.try_clone().map_err(Error::EventFd)?,
            ))),
            0x3e8,
            0x8,
        )
        .map_err(Error::BusError)?;
    self.io_bus
        .insert(
            Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
            ))),
            0x2e8,
            0x8,
        )
        .map_err(Error::BusError)?;
    self.io_bus
        .insert(self.i8042.clone(), 0x060, 0x5)
        .map_err(Error::BusError)?;

    vm_fd
        .register_irqfd(&self.com_evt_1_3, 4)
        .map_err(|e| Error::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;
    vm_fd
        .register_irqfd(&self.com_evt_2_4, 3)
        .map_err(|e| Error::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;
    vm_fd
        .register_irqfd(&self.kbd_evt, 1)
        .map_err(|e| Error::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;

    Ok(())
}
```
Source: [firecracker/src/vmm/src/device_manager/legacy.rs](https://github.com/firecracker-microvm/firecracker/blob/a367796e66eeac42d9ce1294c0fbbca6191e9cf3/src/vmm/src/device_manager/legacy.rs#L82)

### VCPU threads and VCPUID

FireCracker spawns and manages each KVM vCPU emulation in a separate POSIX thread. Each such vCPU is neither an OS thread nor a process, but rather an execution mode supported by hardware. Intel VT-x, for instance, is a technology meant for assisting with running virtualized guests natively without requiring any software emulation. Intel’s technology offers two running modes: a. VMX root mode used for the host VMM, and b. VMX non-root mode used for executing guest instructions. It is assisted by a per-guest structure named Virtual Machine Control Structure, which is responsible for saving all context information both host & guest modes need. This technology is used by KVM and thus by FireCracker to run vCPU.

<p align="center">
  <img src="https://i.imgur.com/MUj6Aon.png" alt="FireCracker execution model" />
</p>

FireCracker monitors each vCPU state, including VMExits and ioeventfd interrupts, and handles them accordingly in a state machine.

Have a look here: [https://github.com/firecracker-microvm/firecracker/blob/HEAD/src/vmm/src/vstate/vcpu/mod.rs](https://github.com/firecracker-microvm/firecracker/blob/HEAD/src/vmm/src/vstate/vcpu/mod.rs).

Another feature provided by FireCracker is CPUID feature masking. On x86 the `CPUID` instruction lets you query the processor for its capabilities, a much needed capability for some workloads. When running inside a VM this instruction won’t work well and requires emulation. KVM supports emulating `CPUID` using the `KVM_SET_CPUID2` ioctl which FC leverages. 

### MicroVM Metadata Service (MMDS)

The MMDS is a FireCracker mutable data store which lets the guest access host-provided JSON metadata. A possible use case of this feature is a credential rotation needed inside the guest, controlled by the host.

This feature is consisted of three components:
1. The backend which is simply an API server endpoint allowing (pre-boot) configuration of the MMDS, and insertion & retrieval of data from it
2. An in-memory data store holding JSON objects
3. A minimal, custom made HTTP/TCP/IPv4 stack handling guest requests heading to the MMDS IPv4 address named “Dumbo”

Each frame coming at the virtio-net device from the guest is tested for its destination. If it’s found to be designated at the Metadata Service (and it’s turned on) then it will be forwarded to Dumbo. Afterwards it’ll get checked for a response which will be sent back to the guest given that there is enough room in the device’s ring buffer. If it is not designated at MMDS, it will be sent to the tap device instead.

```rust
// Tries to detour the frame to MMDS and if MMDS doesn't accept it, sends it on the host TAP.
//
// `frame_buf` should contain the frame bytes in a slice of exact length.
// Returns whether MMDS consumed the frame.
fn write_to_mmds_or_tap(
    mmds_ns: Option<&mut MmdsNetworkStack>,
    rate_limiter: &mut RateLimiter,
    frame_buf: &[u8],
    tap: &mut Tap,
    guest_mac: Option<MacAddr>,
) -> Result<bool> {
    let checked_frame = |frame_buf| {
        frame_bytes_from_buf(frame_buf).map_err(|e| {
            error!("VNET header missing in the TX frame.");
            METRICS.net.tx_malformed_frames.inc();
            e
        })
    };
    if let Some(ns) = mmds_ns {
        if ns.detour_frame(checked_frame(frame_buf)?) {
            METRICS.mmds.rx_accepted.inc();

            // MMDS frames are not accounted by the rate limiter.
            rate_limiter.manual_replenish(frame_buf.len() as u64, TokenType::Bytes);
            rate_limiter.manual_replenish(1, TokenType::Ops);

            // MMDS consumed the frame.
            return Ok(true);
        }
    }

    // This frame goes to the TAP.

    // Check for guest MAC spoofing.
    if let Some(mac) = guest_mac {
        let _ = EthernetFrame::from_bytes(checked_frame(frame_buf)?).map(|eth_frame| {
            if mac != eth_frame.src_mac() {
                METRICS.net.tx_spoofed_mac_count.inc();
            }
        });
    }

    match tap.write(frame_buf) {
        Ok(_) => {
            METRICS.net.tx_bytes_count.add(frame_buf.len());
            METRICS.net.tx_packets_count.inc();
            METRICS.net.tx_count.inc();
        }
        Err(e) => {
            error!("Failed to write to tap: {:?}", e);
            METRICS.net.tap_write_fails.inc();
        }
    };
    Ok(false)
}
```
Source: [firecracker/src/devices/src/virtio/net/device.rs#L395](https://github.com/firecracker-microvm/firecracker/blob/3f1c98c4ba2a50836eab0d50c1adc738180bf56e/src/devices/src/virtio/net/device.rs#L395)

For more info about the design of MMDS and Dumbo checkout these [design docs](https://github.com/firecracker-microvm/firecracker/blob/HEAD/docs/mmds/mmds-design.md).

### Jailer, Seccomp, and cgrouping

Additional sandboxing is added by FireCracker for even better security & performance assurances:
1. Seccomp filters are applied by default to limit syscalls for the host per each of its threads (VMM, API servers, VCPUs). The default ones are the most restrictive, only allowing a minimum set of syscalls and parameters. The other options are having a custom filterset for advanced users, and having no seccomp filters at all which is highly not recommended. Take a look [here](https://github.com/firecracker-microvm/firecracker/blob/main/resources/seccomp/x86_64-unknown-linux-musl.json) for the complete list of default filters.
2. A Jailer process which sets-up all require system resources: creating namespaces, calling `pivot_root()` & `chroot()`, cgrouping, `mknod()`ing special paths like `/dev/kvm` inside the jail, and more. Afterwards it drops privileges and `exec()` into the FireCracker image.
3. The jailer provides support for using cgroups using the `--cgroup` flag. 
4. It also supports using a dedicated netns and/or pid namespace. 


And Voila. That’s it for now. 

It is highly recommended to read the source code of this amazing project and explore it yourselves - [https://github1s.com/firecracker-microvm/firecracker](https://github1s.com/firecracker-microvm/firecracker).
