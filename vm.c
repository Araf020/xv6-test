#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"

extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()

// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
 { (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
 { (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
 { (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
 { (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if((pgdir = (pde_t*)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void*)DEVSPACE)
    panic("PHYSTOP too high");
  for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if(mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                (uint)k->phys_start, k->perm) < 0) {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
  kpgdir = setupkvm();
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
  lcr3(V2P(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
  if(p == 0)
    panic("switchuvm: no process");
  if(p->kstack == 0)
    panic("switchuvm: no kstack");
  if(p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
                                sizeof(mycpu()->ts)-1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort) 0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->pgdir));  // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W|PTE_U);
  memmove(mem, init, sz);
}



void updateQueueRear(struct proc *p) {
  p->memoryQueue.rear = (p->memoryQueue.front + p->pc.memoryPagesCount);
  p->memoryQueue.rear %=  MAX_PSYC_PAGES;
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if((uint) addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, P2V(pa), offset+i, n) != n)
      return -1;
  }
  return 0;
}

static char buff[PGSIZE];

int nextFreeMemoryPage(struct proc *p) {
  if(p->pc.memoryPagesCount != MAX_PSYC_PAGES) return p->memoryQueue.rear;
  return -1;
}

int nextFreeMemoryPageNFU(struct proc *p){
  for (uint i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if(!p->memoryNFU.memoryPages[i].isUsed) return i;
  }
  return -1;
}

void insertToMemoryNFU(struct proc *p, pde_t *pgdir, uint virtualAddress) {

  int index;
  index = nextFreeMemoryPageNFU(p);
  p->pc.memoryPagesCount++;
  p->memoryNFU.memoryPages[index].isUsed = 1;
  p->memoryNFU.memoryPages[index].virtualAddress = virtualAddress;
  p->memoryNFU.memoryPages[index].pgdir = pgdir;
  p->memoryNFU.memoryPages[index].counter = 0;
}

void insertToMemory(struct proc *p, pde_t *pgdir, uint virtualAddress) {

  int index;
  index = nextFreeMemoryPage(p);
  p->pc.memoryPagesCount++;
  p->memoryQueue.memoryPages[index].isUsed = 1;
  p->memoryQueue.memoryPages[index].virtualAddress = virtualAddress;
  p->memoryQueue.memoryPages[index].pgdir = pgdir;
  updateQueueRear(p);
}

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  struct proc* p;
  p = myproc();
  char *mem;
  uint a;

  if(newsz >= KERNBASE)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  // If number of pages composing newsz exceeds MAX_TOTAL_PAGES and the current proc is NOT init or shell...
  if (PGROUNDUP(newsz)/PGSIZE > MAX_TOTAL_PAGES) {
  	if(isInit(p)==0){
      return 0;
    }
  }

  a = PGROUNDUP(oldsz);
  for(; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0){
      cprintf("allocuvm out of memory (2)\n");
      deallocuvm(pgdir, newsz, oldsz);
      kfree(mem);
      return 0;
    }
    // If any policy is defined AND current proc is NOT init or shell...
    if (isInit(p)==0){
      if(!NFUPageReplacementAlgo){
        if (p->pc.memoryPagesCount != MAX_PSYC_PAGES) insertToMemory(p, pgdir, a);
	      else swapOut(p, pgdir, a);
      }
	    else{
        if (p->pc.memoryPagesCount != MAX_PSYC_PAGES) insertToMemoryNFU(p, pgdir, a);
	      else swapOutNFU(p, pgdir, a);
      }
    }
  }
  return newsz;
}

void reorderQueue(struct proc *p,int from) {
  if (from < 0)
    panic("called to organize queue with invalid args");
  int i = from;
  
  for (int nextIdx = (from + 1) % MAX_PSYC_PAGES; ; ) { ;
    if (p->memoryQueue.memoryPages[i].isUsed == 0) {
      if(p->memoryQueue.memoryPages[nextIdx].isUsed == 1){
        p->memoryQueue.memoryPages[i] = p->memoryQueue.memoryPages[nextIdx];
        p->memoryQueue.memoryPages[nextIdx].isUsed = 0;
        i = nextIdx;}
    } 
    else if (p->memoryQueue.memoryPages[i].isUsed == 1) i = nextIdx;

    nextIdx = (nextIdx + 1) % MAX_PSYC_PAGES;
    if(nextIdx == p->memoryQueue.rear)break;
  }
}


void removeFromMemoryNFU(struct proc *p, uint virtualAddress, const pde_t *pgdir){

  if (p){
    int i;
    for (i = 0; i < MAX_PSYC_PAGES; i++) {
      if (p->memoryNFU.memoryPages[i].virtualAddress == virtualAddress)
          if(p->memoryNFU.memoryPages[i].isUsed == 1)
            if(p->memoryNFU.memoryPages[i].pgdir == pgdir){
              p->memoryNFU.memoryPages[i].isUsed = 0;
              p->memoryNFU.memoryPages[i].counter = 0;
              p->pc.memoryPagesCount--;
              return;
            }
    }
  }
}

void removeFromMemory(struct proc *p, uint virtualAddress, const pde_t *pgdir){
  if (p){
    int i;
    for (i = 0; i < MAX_PSYC_PAGES; i++) {
      if (p->memoryQueue.memoryPages[i].virtualAddress == virtualAddress)
          if(p->memoryQueue.memoryPages[i].isUsed == 1)
            if(p->memoryQueue.memoryPages[i].pgdir == pgdir){
              p->memoryQueue.memoryPages[i].isUsed = 0;
              p->pc.memoryPagesCount--;
              reorderQueue(p, i);
              updateQueueRear(p);
              return;
            }
    }
  }
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  uint a, pa;
  struct proc* p;
  p = myproc();

  if(p == 0)
    return oldsz;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for(; a  < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte)
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v;
      int notInitialProcs = (isInit(p)==0);
      v = P2V(pa);
      kfree(v);
      if (notInitialProcs){
        if(!NFUPageReplacementAlgo) removeFromMemory(p, a, pgdir);
        else removeFromMemoryNFU(p, a, pgdir);
      }
      *pte = 0;
    }
  }
  return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void
freevm(pde_t *pgdir)
{
  uint i;

  if(pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for(i = 0; i < NPDENTRIES; i++){
    if(pgdir[i] & PTE_P){
      char * v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char*)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if(pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

void updateFlags(pte_t *pte, int isOut, int pagePAddr){
  if(isOut==1){
    *pte &= ~PTE_P;
    *pte |= PTE_PG;                      
    *pte &= PTE_FLAGS(*pte);
  }

  else if(isOut==0){
    *pte &= ~PTE_PG;
    *pte |= PTE_P | PTE_W | PTE_U;                           
    *pte |= pagePAddr; 
  }
}

void updateFlagsMemoryIn(struct proc* p, int virtualAddress, int pagePAddr, pde_t * pgdir){

  pte_t *pte;
  pte = walkpgdir(pgdir, (int*)virtualAddress, 0);

  if (!pte)
    panic("updateFlagsMemoryIn: pte does NOT exist in pgdir");

  if (*pte & PTE_P)
    panic("updateFlagsMemoryIn: page is already in memory!");

  updateFlags(pte, 0, pagePAddr);

  lcr3(V2P(p->pgdir)); //refresh CR3 register
}

void updateFlagsMemoryOut(struct proc* p, int virtualAddress, pde_t * pgdir){

  pte_t *pte;
  pte = walkpgdir(pgdir, (int*)virtualAddress, 0);
  if (!pte)
    panic("updateFlagsMemoryOut: pte does NOT exist in pgdir");

  updateFlags(pte, 1, 0);

  lcr3(V2P(p->pgdir));      // Refresh CR3 register
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  struct proc* p;
  p = myproc();
  if(!p) return 0;

  if((d = setupkvm()) == 0)
    return 0;
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
      panic("copyuvm: pte should exist");
    if (*pte & PTE_PG){
      updateFlagsMemoryOut(p, i, d);
      continue;
    }
    if(!(*pte & PTE_P))
      panic("copyuvm: page not present");
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, (char*)P2V(pa), PGSIZE);
    if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags) < 0) {
      kfree(mem);
      goto bad;
    }
  }
  return d;

bad:
  freevm(d);
  return 0;
}

//PAGEBREAK!
// Map user virtual address to kernel address.
char*
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if((*pte & PTE_P) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  return (char*)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char*)p;
  while(len > 0){
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char*)va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if(n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.

int nextReplacableMemoryPage(struct proc *p){
  return p->memoryQueue.front;
}

int nextReplacableMemoryPageNFU(struct proc *p){
  uint i, min_ind = 0;
  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if(!p->memoryNFU.memoryPages[i].isUsed) continue;
    int min = p->memoryNFU.memoryPages[min_ind].counter;
    int curr = p->memoryNFU.memoryPages[i].counter;
    if(curr < min) min_ind = i;
  }
  return min_ind;
}


uint getPhysicalAddress(int virtualAddress, pde_t *pgdir){
  pte_t* pte;
  pte = walkpgdir(pgdir, (int*)virtualAddress, 0);
  if(!pte){
    return -1;
  }
  return PTE_ADDR(*pte);
}



int PageWasSwapped(struct proc *p, int virtualAddress) {
  int va;
  va = virtualAddress;
  pte_t *pte = walkpgdir(p->pgdir, (char *)va, 0);
  return (*pte & PTE_PG);
}

void shiftQueue(struct proc *p) {
  p->memoryQueue.front = (p->memoryQueue.front+1)%MAX_PSYC_PAGES;
  p->memoryQueue.rear = (p->memoryQueue.rear+1)%MAX_PSYC_PAGES;
}

int nextFreeSwapPage(struct proc *p) {
  int i;
  i=0;
  while (i < MAX_FILE_PAGES)
  {
    if (p->swapPages[i].isUsed == 0)
      return i;
    i++;
  }

  return -1;
}

int pageToMemoryNFU(struct proc* p, int memoryIndex, uint virtualAddress, char* buff) {

  int ret;
  ret = -1;
  int i = 0;
  uint SwapVirtualAddress;
  while (i < MAX_FILE_PAGES)
  {
    SwapVirtualAddress = p->swapPages[i].virtualAddress;
    if (SwapVirtualAddress == virtualAddress) {
      ret = readFromSwapFile(p, buff, i*PGSIZE, PGSIZE);
      if (ret == -1)
        break;
      p->pc.swapFilePagesCount--;
      p->memoryNFU.memoryPages[memoryIndex] = p->swapPages[i];
      p->swapPages[i].isUsed = 0;
      return ret;
    }
    i++;
  }
  
  return -1;
}

int pageToMemory(struct proc* p, int memoryIndex, uint virtualAddress, char* buff) {

  int ret;
  ret = -1;
  int i = 0;
  uint SwapVirtualAddress;
  while (i < MAX_FILE_PAGES)
  {
    SwapVirtualAddress = p->swapPages[i].virtualAddress;
    if (SwapVirtualAddress == virtualAddress) {
      ret = readFromSwapFile(p, buff, i*PGSIZE, PGSIZE);
      if (ret == -1)
        break;
      p->pc.swapFilePagesCount--;
      p->memoryQueue.memoryPages[memoryIndex] = p->swapPages[i];
      p->swapPages[i].isUsed = 0;
      return ret;
    }
    i++;
  }
  
  return -1;
}


int pageToSwap(struct proc * p, uint virtualAddress, pde_t *pgdir) {
  
  int index;
  index = nextFreeSwapPage(p);
  
  if(index==-1) return -1;

  if(writeToSwapFile(p, (char*)virtualAddress, PGSIZE*index, PGSIZE) == -1)
    return -1;
  
  
  p->swapPages[index].isUsed = 1;
  p->pc.swapFilePagesCount++;
  p->swapPages[index].virtualAddress = virtualAddress;
  p->swapPages[index].pgdir = pgdir;
  
  

  return index;
}

void swapOutNFU(struct proc *p, pde_t *pgdir, uint virtualAddress){

  // Get the page index to replace according to replacement algorithm
  int replace_index;
  struct page_t swappedPage;
  uint pagePhysicalAddress;
  char *va;
  replace_index = nextReplacableMemoryPageNFU(p);
  swappedPage = p->memoryNFU.memoryPages[replace_index];
  pagePhysicalAddress = getPhysicalAddress(p->memoryNFU.memoryPages[replace_index].virtualAddress, p->memoryNFU.memoryPages[replace_index].pgdir);
  va = (char*)P2V(pagePhysicalAddress);

  // write the selected page from memory to swap and free that page in memory
  pageToSwap(p, p->memoryNFU.memoryPages[replace_index].virtualAddress, p->memoryNFU.memoryPages[replace_index].pgdir);

  kfree(va);
  // Update Flags in memory
  updateFlagsMemoryOut(p, swappedPage.virtualAddress, swappedPage.pgdir);

  // states and counter update
  p->memoryNFU.memoryPages[replace_index].isUsed = 0;
  p->pc.memoryPagesCount--;

  // Finds queue rear and inserts new page there
  insertToMemoryNFU(p, pgdir, virtualAddress);
}


void swapOut(struct proc *p, pde_t *pgdir, uint virtualAddress){

  // Get the page index to replace according to replacement algorithm
  int replace_index;
  struct page_t swappedPage;
  uint pagePhysicalAddress;
  char *va;
  replace_index = nextReplacableMemoryPage(p);
  swappedPage = p->memoryQueue.memoryPages[replace_index];
  pagePhysicalAddress = getPhysicalAddress(p->memoryQueue.memoryPages[replace_index].virtualAddress, p->memoryQueue.memoryPages[replace_index].pgdir);
  va = (char*)P2V(pagePhysicalAddress);

  // write the selected page from memory to swap and free that page in memory
  pageToSwap(p, p->memoryQueue.memoryPages[replace_index].virtualAddress, p->memoryQueue.memoryPages[replace_index].pgdir);

  kfree(va);
  // Update Flags in memory
  updateFlagsMemoryOut(p, swappedPage.virtualAddress, swappedPage.pgdir);

  // states and counter update
  p->memoryQueue.memoryPages[replace_index].isUsed = 0;
  p->pc.memoryPagesCount--;

  // Finds queue rear and inserts new page there
  insertToMemory(p, pgdir, virtualAddress);
  shiftQueue(p);
}


int swapIn(struct proc* p, int page_index){
  if(!NFUPageReplacementAlgo){
    // This function is called from trap when page fault occurs
    p->pc.pageFaultCount++;

    //Allocating space for new page
    char* new_allocated_page = kalloc();
    memset(new_allocated_page, 0, PGSIZE);
    lcr3(V2P(p->pgdir));
    int AvailableMemoryIndex = nextFreeMemoryPage(p);
    

    uint virtualAddress = PGROUNDDOWN(page_index);
    // If there is available space in ram no need to swap out
    if (AvailableMemoryIndex >= 0) {
      cprintf("Free index FIFO= %d\n",AvailableMemoryIndex);
      updateFlagsMemoryIn(p, virtualAddress, V2P(new_allocated_page), p->pgdir);
      pageToMemory(p, AvailableMemoryIndex, virtualAddress, (char*)virtualAddress);
      return 1;
    }


    //Swapping-out is needed, Much like swapout
    // Find the available page space in swapfile and return its index in array
    struct page_t outPage;
    int outPagePAddr;
    char *v;

    AvailableMemoryIndex = nextReplacableMemoryPage(p);
    outPage = p->memoryQueue.memoryPages[AvailableMemoryIndex];
    outPagePAddr = getPhysicalAddress(outPage.virtualAddress, outPage.pgdir);
    v = (char*)P2V(outPagePAddr);

    cprintf("Replacable index FIFO= %d\n",AvailableMemoryIndex);
    updateFlagsMemoryIn(p, virtualAddress, V2P(new_allocated_page), p->pgdir);
    pageToMemory(p, AvailableMemoryIndex, virtualAddress, buff);

    memmove(new_allocated_page, buff, PGSIZE);

    pageToSwap(p, outPage.virtualAddress, outPage.pgdir);
    updateFlagsMemoryOut(p, outPage.virtualAddress, outPage.pgdir);

    kfree(v);
    shiftQueue(p);
    return 1;
    }

  else
  {
    // This function is called from trap when page fault occurs
    p->pc.pageFaultCount++;

    //Allocating space for new page
    char* new_allocated_page = kalloc();
    memset(new_allocated_page, 0, PGSIZE);
    lcr3(V2P(p->pgdir));
    int AvailableMemoryIndex = nextFreeMemoryPageNFU(p);
    

    uint virtualAddress = PGROUNDDOWN(page_index);
    // If there is available space in ram no need to swap out
    if (AvailableMemoryIndex >= 0) {
      cprintf("Free index NFU= %d\n",AvailableMemoryIndex);
      updateFlagsMemoryIn(p, virtualAddress, V2P(new_allocated_page), p->pgdir);
      pageToMemoryNFU(p, AvailableMemoryIndex, virtualAddress, (char*)virtualAddress);
      return 1;
    }


    //Swapping-out is needed, Much like swapout
    // Find the available page space in swapfile and return its index in array
    struct page_t outPage;
    int outPagePAddr;
    char *v;

    AvailableMemoryIndex = nextReplacableMemoryPageNFU(p);
    outPage = p->memoryNFU.memoryPages[AvailableMemoryIndex];
    outPagePAddr = getPhysicalAddress(outPage.virtualAddress, outPage.pgdir);
    v = (char*)P2V(outPagePAddr);

    cprintf("Replacable index NFU= %d\n",AvailableMemoryIndex);
    updateFlagsMemoryIn(p, virtualAddress, V2P(new_allocated_page), p->pgdir);
    pageToMemoryNFU(p, AvailableMemoryIndex, virtualAddress, buff);

    memmove(new_allocated_page, buff, PGSIZE);

    pageToSwap(p, outPage.virtualAddress, outPage.pgdir);
    updateFlagsMemoryOut(p, outPage.virtualAddress, outPage.pgdir);

    kfree(v);
    return 1;
  }
  
}

void updateCounters(struct proc* p){
  if(!NFUPageReplacementAlgo) panic("Wrong algo");

  for (uint i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if(!p->memoryNFU.memoryPages[i].isUsed) continue;
    uint virtualAddress = p->memoryNFU.memoryPages[i].virtualAddress;
    pte_t* pte = walkpgdir(p->memoryNFU.memoryPages[i].pgdir, (char*) virtualAddress, 0);
    
    if(!pte) panic("NULL");
    if (*pte & PTE_PG){
      p->memoryNFU.memoryPages[i].counter=0;
      continue;
    }
    if (*pte & PTE_A){
       p->memoryNFU.memoryPages[i].counter++;
       *pte &= ~PTE_A;
    }
    lcr3(V2P(p->pgdir));    
  }
  
}