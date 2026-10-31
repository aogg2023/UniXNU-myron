/* Minimal EFI loader that boots the data-a-live XNU kernel with data-a-live's boot contract.
 * Reads the XNUP payload at 0xF0000000: kernel Mach-O, Apple device tree ("adt"), cmdline. */
#include <stdint.h>
typedef void *efi_handle; typedef void *efi_system_table;
#define XNUP_BASE 0xF0000000ULL
#define FB_BASE 0xfc800000ULL
#define FB_W 1220u
#define FB_H 2656u
#define FB_STRIDE (1220u*4)
#define PHYS_BASE 0x8c0000000ULL
#define MEM_SIZE 0x13ff00000ULL
#define BOOT_LINE 608
struct xhdr { uint32_t magic, size; };
struct xent { char name[16]; uint32_t size, reserved; };
struct boot_video { uint64_t v_baseAddr, v_display, v_rowBytes, v_width, v_height, v_depth; };
struct boot_args {
  uint16_t Revision, Version;
  uint64_t virtBase, physBase, memSize, topOfKernelData;
  struct boot_video Video;
  uint32_t machineType;
  uint64_t deviceTreeP;
  uint32_t deviceTreeLength;
  char CommandLine[BOOT_LINE];
  uint64_t bootFlags, memSizeActual;
};
static uint64_t align_up(uint64_t v, uint64_t a){ return (v + a - 1) & ~(a - 1); }
static void copy_bytes(uint64_t dst, uint64_t src, uint64_t n){
  volatile uint64_t *d = (volatile uint64_t *)(uintptr_t)dst;
  volatile const uint64_t *s = (volatile const uint64_t *)(uintptr_t)src;
  for (uint64_t i = 0; i < (n + 7) / 8; i++) d[i] = s[i];
}
static void zero_bytes(uint64_t dst, uint64_t n){
  volatile uint64_t *d = (volatile uint64_t *)(uintptr_t)dst;
  for (uint64_t i = 0; i < n / 8; i++) d[i] = 0;
}
static uint64_t str_len(const char *s){ uint64_t n=0; while (s[n]) n++; return n; }
static int find_entries(const uint8_t **kernel, uint64_t *klen, const uint8_t **adt, uint64_t *alen, const char **cmd){
  const struct xhdr *h = (const struct xhdr *)(uintptr_t)XNUP_BASE;
  if (h->magic != 0x50554E58u) return 0;
  uint64_t end = XNUP_BASE + 8 + h->size;
  uint64_t p = XNUP_BASE + 8;
  *kernel = 0; *adt = 0; *cmd = "";
  while (p + 24 <= end) {
    const struct xent *e = (const struct xent *)(uintptr_t)p;
    if (e->name[0] == 0) break;
    const uint8_t *data = (const uint8_t *)(uintptr_t)(p + 24);
    if (e->name[0]=='k' && e->name[1]=='e' && e->name[2]=='r' && e->name[3]=='n' && e->name[4]=='e' && e->name[5]=='l' && e->name[6]==0) { *kernel = data; *klen = e->size; }
    else if (e->name[0]=='a' && e->name[1]=='d' && e->name[2]=='t' && e->name[3]==0) { *adt = data; *alen = e->size; }
    else if (e->name[0]=='c' && e->name[1]=='m' && e->name[2]=='d' && e->name[3]=='l' && e->name[4]=='i' && e->name[5]=='n' && e->name[6]=='e' && e->name[7]==0) { *cmd = (const char *)data; }
    p = p + 24 + ((e->size + 15) & ~15ULL);
  }
  return *kernel != 0;
}
static void jump_to_kernel(uint64_t entry, uint64_t boot_args) __attribute__((noreturn));
static void jump_to_kernel(uint64_t entry, uint64_t boot_args){
  __asm__ volatile(
    "msr daifset, #0xf\n"
    "mrs x2, sctlr_el1\n"
    "bic x2, x2, #0x1\n"
    "bic x2, x2, #0x4\n"
    "bic x2, x2, #0x1000\n"
    "msr sctlr_el1, x2\n"
    "isb\n"
    "ic iallu\n"
    "dsb sy\n"
    "isb\n"
    "mov x0, %1\n"
    "br %0\n" : : "r"(entry), "r"(boot_args) : "x0","x2","x3");
  __builtin_unreachable();
}
typedef struct { uint8_t hdr[24]; void *fw_vendor; uint32_t fw_rev; uint8_t pad[4];
  void *con_in_handle; void *con_in; void *con_out_handle; void *con_out;
  void *stderr_handle; void *stderr; void *rts; void *bs; uint64_t num; void *cfg; } systab_t;
typedef struct { uint8_t hdr[24]; void *raise; void *restore;
  uint64_t (*alloc_pages)(uint32_t, uint32_t, uint64_t, uint64_t *);
  uint64_t (*free_pages)(uint64_t, uint64_t);
  uint64_t (*get_memory_map)(uint64_t *, void *, uint64_t *, uint64_t *, uint32_t *); } bootsvc_t;
int efi_main(efi_handle image, efi_system_table *st){
  (void)image;
  bootsvc_t *bgbs = (bootsvc_t *)((systab_t *)st)->bs;
  (void)bgbs;
  const uint8_t *kernel, *adt; uint64_t klen = 0, alen = 0; const char *cmd;
  if (!find_entries(&kernel, &klen, &adt, &alen, &cmd)) return 1;
  const uint8_t *k = kernel;
  if (*(const uint32_t *)k != 0xfeedfacf) return 2;
  uint32_t ncmds = *(const uint32_t *)(k + 16);
  uint64_t p = 32, vm_lo = ~0ULL, vm_hi = 0, entry_va = 0;
  typedef struct { uint64_t vmaddr, vmsize, fileoff, filesize; } seg_t;
  seg_t segs[64]; int nsegs = 0;
  for (uint32_t i = 0; i < ncmds; i++) {
    uint32_t c = *(const uint32_t *)(k + p), sz = *(const uint32_t *)(k + p + 4);
    if (c == 0x19) { /* LC_SEGMENT_64 */
      seg_t s;
      s.vmaddr = *(const uint64_t *)(k + p + 24);
      s.vmsize = *(const uint64_t *)(k + p + 32);
      s.fileoff = *(const uint64_t *)(k + p + 40);
      s.filesize = *(const uint64_t *)(k + p + 48);
      if (nsegs < 64) segs[nsegs++] = s;
      if (s.vmaddr < vm_lo) vm_lo = s.vmaddr;
      if (s.vmaddr + s.vmsize > vm_hi) vm_hi = s.vmaddr + s.vmsize;
    }
    p += sz;
  }
  /* the kernel's entry is the Mach-O LC_MAIN (0x80000028) or fall back to __TEXT + header */
  p = 32;
  for (uint32_t i = 0; i < ncmds; i++) {
    uint32_t c = *(const uint32_t *)(k + p), sz = *(const uint32_t *)(k + p + 4);
    if (c == 0x80000028u) { entry_va = vm_lo + *(const uint64_t *)(k + p + 8); break; }
    p += sz;
  }
  if (entry_va == 0) entry_va = vm_lo + 0x4000;
  /* reserve a RAM window through the firmware so nothing it owns is overwritten */
  uint64_t phys_base = 0, mem_size = 0;
  {
    for (uint64_t pages = 0x40000; pages >= 0x8000; pages >>= 1) {
      uint64_t addr = 0;
      if (bgbs->alloc_pages(0, 2, pages, &addr) == 0) {
        uint64_t aligned = (addr + 0x1FFFFFFULL) & ~0x1FFFFFFULL;
        uint64_t end = addr + (pages << 12);
        if (end > aligned + 0x20000000ULL) { phys_base = aligned; mem_size = end - aligned; break; }
        bgbs->free_pages(addr, pages);
      }
    }
    if (phys_base == 0) return 4;
    if (mem_size > 0x13ff00000ULL) mem_size = 0x13ff00000ULL;
  }
  uint64_t virt_base = vm_lo & ~(0x2000000ULL - 1);
  uint64_t pa_of_va = phys_base - virt_base;
  uint64_t kern_end_pa = align_up(vm_hi + pa_of_va, 0x4000ULL);
  uint64_t adt_pa = kern_end_pa;
  uint64_t ba_pa = align_up(adt_pa + alen, 0x4000ULL);
  uint64_t top = ba_pa + 0x4000;
  if (top > phys_base + mem_size) return 3;
  for (int i = 0; i < nsegs; i++) {
    uint64_t dst = segs[i].vmaddr + pa_of_va;
    copy_bytes(dst, (uint64_t)(uintptr_t)(kernel + segs[i].fileoff), segs[i].filesize);
    if (segs[i].vmsize > segs[i].filesize) zero_bytes(dst + segs[i].filesize, segs[i].vmsize - segs[i].filesize);
  }
  copy_bytes(adt_pa, (uint64_t)(uintptr_t)adt, alen);
  zero_bytes(ba_pa, 0x4000);
  volatile struct boot_args *ba = (volatile struct boot_args *)(uintptr_t)ba_pa;
  ba->Revision = 2; ba->Version = 2;
  ba->virtBase = virt_base;
  ba->physBase = phys_base;
  ba->memSize = mem_size;
  ba->topOfKernelData = top;
  ba->Video.v_baseAddr = FB_BASE;
  ba->Video.v_display = 0; /* -v: show kernel text */
  ba->Video.v_rowBytes = FB_STRIDE;
  ba->Video.v_width = FB_W;
  ba->Video.v_height = FB_H;
  ba->Video.v_depth = 32;
  ba->deviceTreeP = adt_pa - pa_of_va;
  ba->deviceTreeLength = (uint32_t)alen;
  uint64_t n = 0; const char *c = cmd;
  while (*c && n < BOOT_LINE - 1) ba->CommandLine[n++] = *c++;
  ba->bootFlags = 0;
  ba->memSizeActual = mem_size;
  jump_to_kernel(entry_va + pa_of_va, ba_pa);
}