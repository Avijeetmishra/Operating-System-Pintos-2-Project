#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
int sys_exit (int status);

struct fd_elem
{
    int fd;
    struct file *file;
    struct list_elem elem;
    struct list_elem thread_elem;
};

struct fd_buffer {
  int ref_count;
  char fd_buf[244];
  int first;
  int last;
  struct lock buf_lock;
};

int sys_halt (void);
void syscall_init (void);
int sys_exec (struct intr_frame *);
int sys_wait (struct intr_frame *);
int sys_create (struct intr_frame *);
int sys_remove (struct intr_frame *);
int sys_open (struct intr_frame *);
int sys_filesize (struct intr_frame *);
int sys_read (struct intr_frame *);
int sys_write (struct intr_frame *);
int sys_seek (struct intr_frame *);
int sys_tell (struct intr_frame *);
int sys_close (int i);
#endif /* userprog/syscall.h */
