#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"





/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
}



/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL && inode->data.is_dir)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}

struct dir *
dir_open_path (const char *dir)
{
  struct dir *last = get_last_directory (dir);
  if (last == false) {
    return false;
  }
  if (strcmp (dir, "/") == false)
    {
      dir_close (last);
      return dir_open_root ();
    }

  char *dirname = malloc (NAME_MAX + 1);
  char *iterpath = malloc (strlen (dir) + 1);
  char *path = iterpath;
  strlcpy (path, dir, strlen (dir) + 1);
  while (get_next_part (dirname, &path) == 1);
  free (iterpath);
  struct inode *i;
  dir_lookup (last, dirname, &i);
  free (dirname);
  dir_close (last);
  return dir_open (i);
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir)
{
  ASSERT (dir != NULL);
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode)
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, bool is_dir)
{
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */


  // Extend dir
  struct dir_entry e;
  off_t o = 0;
  bool empty = false;
  while (inode_read_at (dir->inode, &e, sizeof e, o) == sizeof e)
    {
      if (e.in_use == false)
        {
          empty = true;
          break;
        }
      o += sizeof e;
    }
  if (empty == false)
    {
      int new = dir->inode->data.length + sizeof e - (dir->inode->data.length % sizeof e);
      new += BLOCK_SECTOR_SIZE - (new % BLOCK_SECTOR_SIZE); 

      sema_down (&dir->inode->inode_lock);
      bool resized = inode_resize (&dir->inode->data, new);
      sema_up (&dir->inode->inode_lock);

      if (resized == true)
        cache_write_block (dir->inode->sector, &dir->inode->data);
      else
        return false;
    }

  /* Write slot. */
  e.in_use = true;
  e.is_dir = is_dir;
  if (is_dir == true)
    {
      if (dir_create (inode_sector, BLOCK_SECTOR_SIZE / sizeof (struct dir_entry)) == false)
        return false;

      struct inode *inode = inode_open (inode_sector);
      if (inode == false)
        return false;

      struct dir *new_dir = dir_open (inode);
      if (new_dir == false || add_default_directories (new_dir, dir) == false)
        return false;
      dir_close (new_dir);
    }


  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, o) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Check if it is a non-empty directory */
  if (e.is_dir)
    {
      struct dir *dir_to_delete = dir_open (inode);
      if (!dir_is_empty (dir_to_delete))
        {
          dir_close (dir_to_delete);
          return false;
        }
    }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;
      if (e.in_use && strcmp (e.name, "..") && strcmp (e.name, "."))
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  return false;
}


bool
dir_is_empty (struct dir *dir)
{
  char tmp[NAME_MAX + 1];
  struct dir *directory = dir_reopen(dir);
  if(dir_readdir (directory, tmp) == true){
    return false;
  }
  else{
    return true;
  }
}

bool
add_default_directories (struct dir *dir, struct dir *parent_dir)
{
  struct dir_entry e;

  //parent
  sema_down (&parent_dir->inode->inode_lock);
  block_sector_t parent = parent_dir->inode->sector;
  bool p = !parent_dir->inode->removed;
  sema_up (&parent_dir->inode->inode_lock);

  struct dir_entry new_dirs[2];

  e.inode_sector = parent;
  off_t ori = dir->pos;
  strlcpy (e.name, "..", NAME_MAX + 1);
  e.is_dir = true;
  e.in_use = p;
  dir->pos += sizeof (e);
  new_dirs[0] = e;

  //current
  sema_down (&dir->inode->inode_lock);
  e.inode_sector = dir->inode->sector;
  e.in_use = !dir->inode->removed;
  sema_up (&dir->inode->inode_lock);
  strlcpy (e.name, ".", NAME_MAX + 1);
  e.is_dir = true;
  new_dirs[1] = e;

  if (inode_write_at (dir->inode, new_dirs, 2 * sizeof (e), ori) == false)
    {
      return false;
    }
  else
  {
    dir->pos += sizeof (e);
      return true;
  }
  
}

bool
is_valid_dir (const char *dir)
{
  struct dir *last = get_last_directory (dir);
  if (last == false) {
    return false;
  }
  if (strcmp (dir, "/") == false)
    return true;

  char *dirname = malloc (NAME_MAX + 1);
  char *iterpath = malloc (strlen (dir) + 1);
  char *path = iterpath;

  strlcpy (path, dir, strlen (dir) + 1);
  while (get_next_part (dirname, &path) == 1);
  free (iterpath);
  struct inode *inode;
  struct dir_entry e;
  size_t ofs;

  for (ofs = 0; inode_read_at (last->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use == true)
      {
        if(strcmp (dirname, e.name) == false)
        {
          if (e.is_dir == false)
            break;
          free (dirname);
          dir_close (last);
          return true;
        }
      }
  dir_close (last);
  free (dirname);
  return false;
}