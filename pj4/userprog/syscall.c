#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static int sys_halt (void);
static int sys_exit (int status);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static int sys_create (const char *ufile, unsigned initial_size);
static int sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static int sys_close (int handle);
static int sys_practice (int num);
static bool sys_chdir (const char *dir);
static bool sys_mkdir (const char *dir);
static bool sys_readdir (int fd, char *name);
static bool sys_isdir (int fd);
static int sys_inumber (int fd);
static int sys_clearcache (void);
static int sys_diskwrites (void);
static int sys_diskreads (void);

static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* file descriptor struct */
struct file_descriptor
{
  struct list_elem elem;      /* List element. */
  struct file *file;          /* File. */
  struct dir *dir;            /* Directory. */
  bool is_dir;                /* Is directory */
  int handle;                 /* File handle. */
};

/* Returns the file descriptor given the handle. */
static struct file_descriptor *
searchfile (int handle)
{
  struct thread *cur = thread_current ();
  struct list_elem *element;
  for (element = list_begin (&cur->fds); element != list_end (&cur->fds);element = list_next (element))
    {
      struct file_descriptor *fd;
      fd = list_entry (element, struct file_descriptor, elem);
      if (fd->handle == handle)
        return fd;
    }
  thread_exit ();
  return NULL;
}

/* Returns true if UADDR is a valid, otherwise return false. */
static bool
verify_user (const void *uaddr)
{
  if (uaddr < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL)
    return true;
  else
    return false;
}

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}

/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size)
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc))
      thread_exit ();
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us)
{
  char *ks;
  size_t length;

  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();

  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++))
        {
          palloc_free_page (ks);
          thread_exit ();
        }

      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
  typedef int syscall_function (int, int, int);

  /* A system call. */
  struct syscall
    {
      size_t arg_cnt;           /* Number of arguments. */
      syscall_function *func;   /* Implementation. */
    };

  /* Table of system calls. */
  static const struct syscall syscall_table[] =
    {
      {0, (syscall_function *) sys_halt},
      {1, (syscall_function *) sys_exit},
      {1, (syscall_function *) sys_exec},
      {1, (syscall_function *) sys_wait},
      {2, (syscall_function *) sys_create},
      {1, (syscall_function *) sys_remove},
      {1, (syscall_function *) sys_open},
      {1, (syscall_function *) sys_filesize},
      {3, (syscall_function *) sys_read},
      {3, (syscall_function *) sys_write},
      {2, (syscall_function *) sys_seek},
      {1, (syscall_function *) sys_tell},
      {1, (syscall_function *) sys_close},
      {1, (syscall_function *) sys_practice},
      {0, (syscall_function *) NULL},
      {0, (syscall_function *) NULL}, 
      {1, (syscall_function *) sys_chdir},
      {1, (syscall_function *) sys_mkdir},
      {2, (syscall_function *) sys_readdir},
      {1, (syscall_function *) sys_isdir},
      {1, (syscall_function *) sys_inumber},
      {0, (syscall_function *) sys_clearcache},
      {0, (syscall_function *) sys_diskwrites},
      {0, (syscall_function *) sys_diskreads},
    };

  const struct syscall *sc;
  unsigned call_nr;
  int args[3];

  /* Get the system call. */
  copy_in (&call_nr, f->esp, sizeof call_nr);
  if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
    thread_exit ();
  sc = syscall_table + call_nr;

  /* Get the system call arguments. */
  ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);

  /* Execute the system call,
     and set the return value. */
  f->eax = sc->func (args[0], args[1], args[2]);
}

/* Halt system call. */
static int
sys_halt (void)
{
  shutdown_power_off ();
}

/* Exit system call. */
static int
sys_exit (int exit_code)
{
  thread_current ()->wait_status->exit_code = exit_code;
  thread_exit ();
  NOT_REACHED ();
}

/* Exec system call. */
static int
sys_exec (const char *ufile)
{
  tid_t tid;
  char *kfile = copy_in_string (ufile);
  tid = process_execute (kfile);
  palloc_free_page (kfile);
  return tid;
}

/* Wait system call. */
static int
sys_wait (tid_t child)
{
  return process_wait (child);
}

/* Create system call. */
static int
sys_create (const char *ufile, unsigned initial_size)
{
  char *kfile = copy_in_string (ufile);
  bool success;
  success = filesys_create (kfile, initial_size);
  palloc_free_page (kfile);
  return success;
}

/* Remove system call. */
static int
sys_remove (const char *ufile)
{
  char *kfile = copy_in_string (ufile);
  bool success;
  success = filesys_remove (kfile);
  palloc_free_page (kfile);
  return success;
}

/* Open system call. */
static int
sys_open (const char *ufile)
{
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd = malloc (sizeof *fd);
  int handle = -1;
  if (!is_valid_dir (kfile))
  {
    fd->dir = NULL;
    fd->file = filesys_open (kfile);
    fd->is_dir = false;
    if (fd->file)
    {
      struct thread *cur = thread_current ();
      handle = fd->handle = cur->next_handle++;
      list_push_front (&cur->fds, &fd->elem);
    }
    else
      free (fd);
  }
  else
  {
    fd->dir = dir_open_path (kfile);
    fd->file = NULL;
    fd->is_dir = true;
    if (fd->dir)
    {
      struct thread *cur = thread_current ();
      handle = fd->handle = cur->next_handle++;
      list_push_front (&cur->fds, &fd->elem);
    }
    else
      free (fd);
  }
  palloc_free_page (kfile);
  return handle;
}

/* Filesize system call. */
static int
sys_filesize (int handle)
{
  struct file_descriptor *fd = searchfile (handle);
  int size;
  if (fd->file)
    size = file_length (fd->file);
  else
    size = file_length (fd->dir);
  return size;
}

/* Read system call. */
static int
sys_read (int handle, void *udst_, unsigned size)
{
  uint8_t *udst = udst_;
  struct file_descriptor *fd;
  int bytes = 0;
  if (handle == 0)
  {
    for (bytes = 0; (size_t) bytes < size; bytes++)
      if (udst >= (uint8_t *) PHYS_BASE || !put_user (udst++, input_getc ()))
        thread_exit ();
    return bytes;
  }
  fd = searchfile (handle);
  if (fd->dir)
    return -1;
  while (size > 0)
    {
      size_t page_left = PGSIZE - pg_ofs (udst);
      off_t ret;
      size_t amt;
      if (size < page_left)
        amt = size;
      else
        amt = page_left;
      
      if (!verify_user (udst))
      {
        thread_exit ();
      }
      ret = file_read (fd->file, udst, amt);
      if (ret < 0)
      {
        if (bytes == 0)
          bytes = -1;
        break;
      }
      bytes += ret;
      if (ret != (off_t) amt)
        break;
      udst += ret;
      size -= ret;
    }
  return bytes;
}

/* Write system call. */
static int
sys_write (int handle, void *usrc_, unsigned size)
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd = NULL;
  int bytes = 0;
  if (handle != 1)
    fd = searchfile (handle);
    if (fd && fd->dir)
      return -1;
  while (size > 0)
    {
      size_t page_left = PGSIZE - pg_ofs (usrc);
      off_t ret;
      size_t amt;
      if (size < page_left)
        amt = size;
      else
        amt = page_left;
      if (!verify_user (usrc))
      {
        thread_exit ();
      }
      if (handle == 1)
      {
        putbuf (usrc, amt);
        ret = amt;
      }
      else
        ret = file_write (fd->file, usrc, amt);

      if (ret < 0)
      {
        if (bytes == 0)
          bytes = -1;
        break;
      }
      bytes += ret;
      if (ret != (off_t) amt)
        break;
      usrc += ret;
      size -= ret;
    }
  return bytes;
}

/* Seek system call. */
static int
sys_seek (int handle, unsigned position)
{
  struct file_descriptor *fd = searchfile (handle);
  if ((off_t) position >= 0)
    file_seek (fd->file, position);
  return 0;
}

/* Tell system call. */
static int
sys_tell (int handle)
{
  struct file_descriptor *fd = searchfile (handle);
  unsigned position;
  position = file_tell (fd->file);
  return position;
}

/* Close system call. */
static int
sys_close (int handle)
{
  struct file_descriptor *fd = searchfile (handle);
  file_close (fd->file);
  list_remove (&fd->elem);
  free (fd);
  return 0;
}

/* Practice system call */
static int
sys_practice (int num)
{
  return num + 1;
}
/* Clearcache system call */
int
sys_clearcache (void)
{
  clear_cache();
  return 1;
}
/* Diskwrites system call */
int
sys_diskwrites (void)
{
  return num_disk_writes ();
}
/* Diskreads system call */
int
sys_diskreads (void)
{
  return num_disk_reads ();
}

void get_name(char *dir_name, char *dir)
{
  char *path = malloc (strlen (dir) + 1);
  char *iter_path = path;
  strlcpy (iter_path, dir, strlen (dir) + 1);
  while (get_next_part (dir_name, &iter_path) == 1);
  free (path);
}

/* Change directory system call */
static bool
sys_chdir (const char *dir)
{
  struct dir *last_dir = get_last_directory (dir);
  if (!last_dir) {
    return false;
  }
  char *dir_name = malloc (NAME_MAX + 1);
  get_name(dir_name,dir);
  struct inode *inode;
  dir_lookup (last_dir, dir_name, &inode);
  if (inode)
    {
      dir_close (thread_current ()->cwd);
      thread_current ()->cwd = dir_open (inode);
      free (dir_name);
      return true;
    }
  dir_close (last_dir);
  free (dir_name);
  return false;
}

/* Make directory system call */
static bool
sys_mkdir (const char *dir)
{
  struct dir *last_dir = get_last_directory (dir);
  if (!last_dir) {
    return false;
  }
  char *dir_name = malloc (NAME_MAX + 1);
  get_name(dir_name,dir);
  block_sector_t new_file_sector;
  if (!free_map_allocate (1, &new_file_sector))
    {
      dir_close (last_dir);
      free (dir_name);
      return false;
    }
  if (dir_add (last_dir, dir_name, new_file_sector, true))
    {
      dir_close (last_dir);
      free (dir_name);
      return true;
    }
  else
    {
      if (new_file_sector != 0)
        free_map_release (new_file_sector, 1);
      dir_close (last_dir);
      free (dir_name);
      return false;
    }
}

/* Read directory system call */
static bool
sys_readdir (int fd, char *name)
{
  struct file_descriptor *fds = searchfile (fd);
  if (fds->file)
    return false;
  return dir_readdir (fds->dir, name);
}

struct dir *
get_last_directory (const char *path) {
  if (!path || strcmp(path, "") == 0)
    return NULL;
  if (!thread_current ()->cwd)
    thread_current ()->cwd = dir_open_root ();
  if (*path != '/')
    return get_last_relative_path (path);
  else
    return get_last_absolute_path (path);
}

/* remove all*/
void re(char* part, char* absolute, struct dir* dir,struct dir* prev)
{
  free (part);
  free (absolute);
  dir_close (dir);
  dir_close (prev);
} 

/* open the folder if path is absolute path */
struct dir *
get_last_absolute_path (const char *path) {
  if (!path || strcmp(path, "") == 0)
    return NULL;

  char *part = malloc (NAME_MAX + 1);
  char *absolute = malloc (strlen (path) + 1);
  char *iter_path = absolute;
  strlcpy (absolute, path, strlen (path) + 1);
  int next_part = get_next_part(part, &iter_path);
  if (next_part != 1)
  {
    free (part);
    free (absolute);
    if (next_part == 0)
      return dir_open_root ();
    else
      return NULL; 
  }
  struct dir *dir = dir_open_root ();
  struct dir *prev = dir_reopen (dir);
  struct inode *inode;
  while (next_part) {
    if (next_part != -1)
      {
        if (dir_lookup (dir, part, &inode))
          {
            next_part = get_next_part (part, &iter_path);
            dir_close (prev);
            prev = dir;
            dir = dir_open(inode);
          }
        else
          {
            next_part = get_next_part (part, &iter_path);
            if (next_part != 0)
              {
                re(part,absolute,dir,prev);
                return NULL;
              }
            else
              {
                dir_close (prev);
                prev = dir_reopen (dir);
                break;
              }
          }
      }
    else
      {
        printf("File name too long");
        re(part,absolute,dir,prev);
        return NULL;
      }
  }
  dir_close (dir);
  free (part);
  free (absolute);
  return prev;
}


/* open the folder if path is relative path */
struct dir *
get_last_relative_path (const char *path)
{
  if (!path || strcmp(path, "") == 0)
    return NULL;

  char *part = malloc (NAME_MAX + 1);
  char *relative = malloc (strlen (path) + 1);
  char *iter_path = relative;
  strlcpy (relative, path, strlen (path) + 1);
  int next_part = get_next_part(part, &iter_path);
  if (next_part != 1)
  {
    free (part);
    free (relative);
    if (next_part == 0)
      return thread_current ()->cwd;
    else
      return NULL; 
  }
  struct dir *cwd = thread_current ()->cwd;
  struct dir *dir = dir_reopen (cwd);
  struct dir *prev = dir_reopen (cwd);
  struct dir_entry element;
  size_t ofs;
  struct inode *inode = dir->inode;;
  struct inode *prev_inode = prev->inode;
  bool found;
  while (next_part)
    {
      if (next_part == -1)
        {
          re(part,relative,dir,prev);
          return NULL;
        }
      found = false;
      for (ofs = 0; inode_read_at (dir->inode, &element, sizeof element, ofs) == sizeof element;
           ofs += sizeof element)
        if (!strcmp (part, element.name))
          {
            if (element.is_dir) {
              dir_close (prev);
              prev = dir;
              prev_inode = prev->inode;
              inode = inode_open (element.inode_sector);
              dir = dir_open (inode);
              found = true;
            }
            break;
          }
      next_part = get_next_part(part, &iter_path);
      if (next_part == 0)
        {
          if (!found)
            {
              dir_close (prev);
              prev = dir_reopen (dir);
            }
          break;
        }
      if (!found && next_part == 1)
        {
          re(part,relative,dir,prev);
          return NULL;
        }
    }
  dir_close (dir);
  free (part);
  free (relative);
  if (!prev_inode->removed)
    return prev;
  dir_close (prev);
}

/* Isdir directory system call */
static bool
sys_isdir (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *element;
  for (element = list_begin (&cur->fds); element != list_end (&cur->fds); element = list_next (element))
    {
      struct file_descriptor *fds;
      fds = list_entry (element, struct file_descriptor, elem);
      if (fds->handle == fd)
          return fds->is_dir;
    }
  return false;
}

/* Inumber directory system call */
static int
sys_inumber (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *element;
  for (element = list_begin (&cur->fds); element != list_end (&cur->fds); element = list_next (element))
    {
      struct file_descriptor *fds;
      fds = list_entry (element, struct file_descriptor, elem);
      if (fds->handle == fd)
        {
          struct inode *inode;
          if (fds->file)
            inode = fds->file->inode;
          else
            inode = fds->dir->inode;
          return inode_get_inumber (inode);
        }
    }
  return -1;
}

/* Extract a file name part from *SRCP into PART, and updates *SRCP. */
int
get_next_part (char part[NAME_MAX + 1], const char **srcp) {
  const char *src = *srcp;
  char *dst = part;
  if (*src == '\0')
    return 0;
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;
  for (;*src != '/' && *src != '\0'; src++)
  {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
  }
  *dst = '\0';
  *srcp = src; /* update pointer. */
  return 1;
}

/* Exit system call. */
void
syscall_exit (void)
{
  struct thread *cur = thread_current ();
  struct list_elem *element;
  for (element = list_begin (&cur->fds); element != list_end (&cur->fds); element = list_next (element))
    {
      struct file_descriptor *fd;
      fd = list_entry (element, struct file_descriptor, elem);
      file_close (fd->file);
      dir_close (fd->dir);
      free (fd);
    }
  if (!strcmp(cur->name, "main"))
    flush_cache ();
}
