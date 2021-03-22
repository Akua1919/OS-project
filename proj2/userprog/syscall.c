#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <threads/vaddr.h>
#include <filesys/filesys.h>
#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/palloc.h>
#include <threads/malloc.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"

static void syscall_handler (struct intr_frame *);
static void is_valid_address(void * p);
static void check_multiple(int * p, int num);
struct opened_file * search_file(int fd);

void halt(void);
void exit(int * p);
int exec(struct intr_frame *f,int * p);
int wait(struct intr_frame *f,int * p);
int create(struct intr_frame *f,int * p);
int remove(struct intr_frame *f,int * p);
int open(struct intr_frame *f,int * p);
int filesize(struct intr_frame *f,int * p);
int read(struct intr_frame *f,int * p);
int write(struct intr_frame *f,int * p);
void seek(int * p);
int tell(struct intr_frame *f,int * p);
void close(int * p);
mmapid_t map(int* fd, void *);

struct lock sys_lock;

void
syscall_init (void)
{
  lock_init (&sys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void is_valid_address(void *p){
  if (p==NULL || !is_user_vaddr(p) ||!is_user_vaddr(p+4) || !pagedir_get_page(thread_current()->pagedir,p))
  {
  thread_current()->exit_status = -1;
  thread_exit ();
  }
}

void check_multiple(int *p, int num){
  int *p2=p;
  for(int i=0; i<num; i++,p2++)
  {
  is_valid_address(p2);
  }
}

struct opened_file * search_file(int fd){
  struct list_elem *e;
  struct opened_file * opf =NULL;
  struct list *files = &thread_current()->files;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    opf = list_entry (e, struct opened_file, file_elem);
    if (opf->fd==fd)
      return opf;
  }
  return false;
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int * p =f->esp;
  is_valid_address(p);
  int systemcall=*p;
  switch (systemcall){
    case SYS_HALT:
      halt();
    case SYS_EXIT:
      exit(p+1);
    case SYS_EXEC:
      exec(f,p+1);
      break;
    case SYS_WAIT:
      wait(f,p+1);
      break;
    case SYS_CREATE:
      create(f,p+1);
      break;
    case SYS_REMOVE:
      remove(f,p+1);
      break;     
    case SYS_OPEN:
      open(f,p+1);
      break;
    case SYS_FILESIZE:
      filesize(f,p+1);
      break;
    case SYS_READ:
      read(f,p+1);
      break;
    case SYS_WRITE:
      write(f,p+1);
      break;
    case SYS_SEEK:
      seek(p+1);
      break;
    case SYS_TELL:
      tell(f,p+1);
      break;
    case SYS_CLOSE:
      close(p+1);
      break;
    case SYS_MMAP:
      f->eax = map(p+1, (void*)(*2+));
      break;
    case SYS_MUNMAP:
      break;
    default:
      thread_current()->exit_status = -1;
      thread_exit ();
      break;
  }
}

// Shut down the pintos
void halt()
{
  shutdown_power_off();
}
// Terminates the current user program
void exit(int * p)
{
  is_valid_address(p);
  thread_current()->exit_status = *p;
  thread_exit ();
}
// Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid).
int exec(struct intr_frame *f,int * p)
{
  is_valid_address(p);
  //Check if it is empty
  if (*p==NULL)
  {
  thread_current()->exit_status = -1;
  thread_exit ();
  }

  f->eax = process_execute(*p);
}
// Waits for a child process pid and retrieves the child's exit status.
int wait(struct intr_frame *f,int * p)
{
  is_valid_address(p);
  f->eax = process_wait(*p);
}
// Creates a new file called file initially initial_size bytes in size.
int create(struct intr_frame *f,int * p)
{
  check_multiple(p, 2);
  //Check if it is empty
  if (*p==NULL)
  {
  thread_current()->exit_status = -1;
  thread_exit ();
  }

  acquire_file_lock();
  f->eax = filesys_create(*p,*(p+1));
  release_file_lock();
}
// Deletes the file called file.
int remove(struct intr_frame *f,int * p)
{
  is_valid_address(p);
  //Check if it is empty
  if (*p==NULL)
  {
  thread_current()->exit_status = -1;
  thread_exit ();
  }

  acquire_file_lock();
  f->eax = filesys_remove((const char *)*p);
  release_file_lock();
}
// Opens the file called file.
int open(struct intr_frame *f,int * p)
{
  is_valid_address(p);
  //Check if it is empty
  if (*p==NULL)
  {
  thread_current()->exit_status = -1;
  thread_exit ();
  }

  struct thread * t=thread_current();
  acquire_file_lock();
  struct file * thefile =filesys_open(*p);
  release_file_lock();

  if(thefile){
  struct opened_file *of = malloc(sizeof(struct opened_file));
  of->fd = t->next_fd++;
  of->file = thefile;
  list_push_back(&t->files, &of->file_elem);
  f->eax = of->fd;
  } else
  f->eax = -1;
}
// Returns the size, in bytes, of the file open as fd.
int filesize(struct intr_frame *f,int * p)
{
  is_valid_address(p);
  struct opened_file * opf = search_file(*p);
  if (opf){
  acquire_file_lock();
  f->eax = file_length(opf->file);
  release_file_lock();
  } 
  else
  {
    f->eax = -1;
  }
}
// Reads size bytes from the file open as fd into buffer.
int read(struct intr_frame *f,int * p)
{
  check_multiple(p, 3);
  is_valid_address(*(p+1));

  int fd = *p;
  char * buffer = *(p+1);
  off_t size = *(p+2);

  if (fd==0) {
    for (int i=0; i<size; i++)
    buffer[i] = input_getc();
    f->eax = size;
  }
  else{
    struct opened_file * opf = search_file(*p);
    if (opf){
      acquire_file_lock();
      f->eax = file_read(opf->file, buffer, size);
      release_file_lock();
    } else
    {
      f->eax = -1;
    }
  }
}
// Writes size bytes from buffer to the open file fd. 
int write(struct intr_frame *f,int * p)
{
  check_multiple(p, 3);
  is_valid_address(*(p+1));

  int fd = *p;
  char * buffer = *(p+1); 
  off_t size = *(p+2);

  if (fd==1) {
    putbuf(buffer,size);
    f->eax = size;
  }
  else{
    struct opened_file * opf = search_file(*p);
    if (opf){
      acquire_file_lock();
      f->eax = file_write(opf->file, buffer, size);
      release_file_lock();
    } else
    {
      f->eax = 0; 
    }
  }
}
// Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file.
void seek(int * p)
{
  check_multiple(p, 2);
  struct opened_file * opf = search_file(*p);
  if (opf){
    acquire_file_lock();
    file_seek(opf->file, *(p+1));
    release_file_lock();
  }
}
// Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
int tell(struct intr_frame *f,int * p)
{
 is_valid_address(p);
  struct opened_file * opf = search_file(*p);
  if (opf){
    acquire_file_lock();
    f->eax = file_tell(opf->file);
    release_file_lock();
  }else
  f->eax = -1;
}
// Closes file descriptor fd. 
void close(int * p)
{
  is_valid_address(p);
  struct opened_file * opf=search_file(*p);
  if (opf){
    acquire_file_lock();
    file_close(opf->file);
    release_file_lock();
    list_remove(&opf->file_elem);
    free(opf);
  }
}

// mmap
mmapid_t map (int* fd, void *upage) {
  
  is_valid_address(fd);
  is_valid_address(*(fd+1));
  if (upage == NULL || pg_ofs(upage) != 0 || fd < 2)
    return -1;

  struct thread *cur = thread_current();

  lock_acquire (&sys_lock);

  /* Open file */
  struct file *file = NULL;
  struct opened_file* node = search_file (*fd);

  if(node && node->file)
    file = file_reopen (node->file);

  /* Check open state */
  if(file == NULL)
    {
      lock_release (&sys_lock);
      return -1;
    }
  size_t file_size = file_length(file);
  if(file_size == 0)
    {
      lock_release (&sys_lock);
      return -1;
    }

  /* Check page addr */
  for (size_t ofs = 0; ofs < file_size; ofs += PGSIZE)
    {
      void *addr = upage + ofs;
      if (get_spte (cur->spt, addr) != NULL)
        {
          lock_release (&sys_lock);
          return -1;
        }
    }
  /* Map pages */
  for (size_t ofs = 0; ofs < file_size; ofs += PGSIZE)
    {
      void *addr = upage + ofs;
      size_t zero_bytes = 0;
      size_t read_bytes = PGSIZE;
      if (ofs + PGSIZE >= file_size)
      {
        read_bytes =  file_size - ofs;
        zero_bytes = PGSIZE - read_bytes;

      }
      spt_add_file (cur->spt, addr, file, ofs, read_bytes, zero_bytes, /*writable*/true);
    }
  /* Assign an id */
  mmapid_t mmapid;
  if (list_empty (&cur->mmap_list))
    mmapid = 1;
  else
    mmapid = list_entry (list_back (&cur->mmap_list), struct mmap_node, elem)->id + 1;

  struct mmap_node *m_node = (struct mmap_node *)malloc (sizeof (struct mmap_node));
  m_node->id = mmapid;
  m_node->file = file;
  m_node->size = file_size;
  m_node->vaddr = upage;
  list_push_back (&cur->mmap_list, &m_node->elem);

  lock_release (&sys_lock);
  return mmapid;
}