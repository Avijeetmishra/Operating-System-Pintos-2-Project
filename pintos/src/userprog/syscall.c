#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#define WORD_SIZE sizeof(void *)

static void syscall_handler (struct intr_frame *);

typedef int pid_t;

//static bool null_validate (void *ptr);
//static struct lock filesys_lock;
static struct list file_list;
static struct lock file_lock;

static struct file *find_file_by_fd (int fd);
static struct fd_elem *find_fd_elem_by_fd (int fd);
static struct fd_elem *elem_get (int fd);

void syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    list_init (&file_list);
    lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
    int *esp = f->esp;
    //int *fd = *(esp + 1);
    int *status = *(esp + 1);
    int syscall_number = *esp;
    //int i;
//    if (esp < SYS_HALT || esp > SYS_INUMBER)
	//	sys_exit (-1);
  /*  if (!is_user_vaddr (esp)){
        sys_exit (-1);
    }*/
    if (!(is_user_vaddr (esp) && is_user_vaddr (esp + 1) && is_user_vaddr (esp + 2) && is_user_vaddr (esp + 3)))
        sys_exit (-1);
	
    switch (syscall_number) {
        case SYS_HALT:
            sys_halt();
            break;
        case SYS_EXIT:
            f->eax = sys_exit(status);
            break;
        case SYS_EXEC:
            f->eax = sys_exec(f);
            break;
        case SYS_WAIT:
            f->eax = sys_wait(f);
            break;
        case SYS_OPEN:
            f->eax = sys_open(f);
            break;
        case SYS_TELL:
            f->eax = sys_tell(f);
            break;
        case SYS_CLOSE:
            f->eax = sys_close(status);
            break;
        case SYS_FILESIZE:
            f->eax = sys_filesize(f);
            break;
        case SYS_READ:
            f->eax = sys_read(f);
            break;
        case SYS_WRITE:
            f->eax = sys_write (f);
            break;
        case SYS_CREATE:
            f->eax = sys_create(f);
            break;
        case SYS_REMOVE:
            f->eax = sys_remove(f);
            break;
        case SYS_SEEK:
            f->eax = sys_seek(f);
            break;
        
    }
    
    //sys_exit (-1);
}

int sys_write (struct intr_frame *frame UNUSED)
{
    int *esp;
    esp = frame->esp;
    int fd = *(esp + 1);
    const char *buffer = *(esp + 2);
    unsigned length = *(esp + 3);
    
    struct file *f;
    int ret = -1;
    lock_acquire (&file_lock);
    if (fd == STDIN_FILENO){
        
    }
    else if (fd == STDOUT_FILENO){
        putbuf (buffer, length);
    }
    else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length))
    {
        lock_release (&file_lock);
        sys_exit (-1);
    }
    else
    {
        f = find_file_by_fd (fd);
        if (!f){
            lock_release (&file_lock);
            return ret;
        }
        
        ret = file_write (f, buffer, length);
    }
    
    lock_release (&file_lock);
    return ret;
}

int sys_exit (int status)
{
    /*Close all files*/
    struct thread *t;
    struct list_elem *l;
    
    t = thread_current ();
    while (!list_empty (&t->files))
    {
        l = list_begin (&t->files);
        sys_close (list_entry (l, struct fd_elem, thread_elem)->fd);
    }
    t->return_stat = status;
    thread_exit ();
    return -1;
}

int sys_halt(void) {
	shutdown_power_off();
}

int sys_create (struct intr_frame *frame UNUSED)
{
    int *esp;
    esp = frame->esp;
    const char *file = *(esp + 1);
    unsigned size = *(esp + 2);
    if (!file)
        return sys_exit (-1);
	//lock_acquire (&file_lock);
    return filesys_create (file, size);
	//lock_release (&file_lock);
}

int sys_close (int i)
{
    //int *esp;
    //esp = frame->esp;
    //int fd = *(esp + 1);
    
    struct fd_elem *f;
    
    f = elem_get (i);
    
    if (!f)
        return 0;
    file_close (f->file);
    list_remove (&f->elem);
    list_remove (&f->thread_elem);
    free (f);
    return 0;
}

int sys_open (struct intr_frame *frame UNUSED){
    int *esp;
    esp = frame->esp;
    int fd = *(esp + 1);
    
    struct file *f;
    struct fd_elem *fde;
    int ret = -1;
    
    if (!fd)
        return ret;
    if (!is_user_vaddr (fd))
        sys_exit (ret);
    f = filesys_open (fd);
    if (!f)
        return ret;
    
    fde = (struct fd_elem *)malloc (sizeof (struct fd_elem));
    if (!fde)
    {
        file_close (f);
        return ret;
    }
    
    fde->file = f;
    fde->fd = 3;
    list_push_back (&file_list, &fde->elem);
    list_push_back (&thread_current ()->files, &fde->thread_elem);
    ret = fde->fd;
    return ret;
}

int sys_read (struct intr_frame *frame UNUSED){
    int *esp;
    esp = frame->esp;
    int fd = *(esp + 1);
    const char *buffer = *(esp + 2);
    unsigned size = *(esp + 3);
    
    struct file *f;
    unsigned i;
    int ret = -1;
    lock_acquire (&file_lock);
    
    if (fd == STDOUT_FILENO) {
        
    }
    else if (fd == STDIN_FILENO)
    {
        for (i = 0; i != size; ++ i)
            *(uint8_t *)(buffer + i) = input_getc ();
        ret = size;
    }
    else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + size))
    {
        lock_release (&file_lock);
        sys_exit (-1);
    }
    else
    {
        f = find_file_by_fd (fd);
        if (!f){
            lock_release (&file_lock);
            return ret;
        }
        ret = file_read (f, buffer, size);
    }
    
    lock_release (&file_lock);
    return ret;
}

int sys_wait (struct intr_frame *frame UNUSED)
{
    unsigned int *esp = frame->esp;
    tid_t t = *(esp + 1);
    return process_wait (t);
}

int sys_filesize (struct intr_frame *frame UNUSED)
{
    unsigned int *esp = frame->esp;
    int fd = *(esp + 1);
    
    struct file *file;
    
    file = find_file_by_fd(fd);
    if (!file)
        return -1;
    return file_length (file);
}

int sys_tell (struct intr_frame *frame UNUSED)
{
    unsigned int *esp = frame->esp;
    int fd = *(esp + 1);
    
    struct file *file;
    
    file = find_file_by_fd (fd);
    if (!file)
        return -1;
    return file_tell (file);
}

int sys_exec (struct intr_frame *frame UNUSED){
    int stat , *esp;
    esp = frame->esp;
    const char *t = *(esp + 1);
    stat = -1;
	
    if (!t || !is_user_vaddr (t))
        return stat;
    lock_acquire (&file_lock);
    stat = process_execute (t);
    lock_release (&file_lock);
    return stat;
}

int sys_remove (struct intr_frame *frame UNUSED)
{
    int *esp;
    esp = frame->esp;
    const char *file = *(esp + 1);
    if (!is_user_vaddr (file))
        sys_exit (-1);
    if (!file)
        return false;
    
    return filesys_remove (file);
}

int sys_seek (struct intr_frame *frame UNUSED)
{
    int *esp;
    esp = frame->esp;
    int fd = *(esp + 1);
    unsigned pos = *(esp + 3);
    
    struct file *file;
    
    file = find_file_by_fd (fd);
    if (!file)
        return -1;
    file_seek (file, pos);
    return 0;
}

static struct fd_elem * find_fd_elem_by_fd (int fd)
{
    struct fd_elem *ret;
    struct list_elem *le;
    
    for (le = list_begin (&file_list); le != list_end (&file_list); le = list_next (le)){
        ret = list_entry (le, struct fd_elem, elem);
        if (ret->fd == fd)
            return ret;
    }
    
    return NULL;
}

static struct file * find_file_by_fd (int fd){
    struct fd_elem *ret;
    
    ret = find_fd_elem_by_fd (fd);
    if (!ret)
        return NULL;
    return ret->file;
}

static struct fd_elem *elem_get (int fd)
{
    struct fd_elem *ret;
    struct thread *t;
    struct list_elem *l;
    
    t = thread_current ();
    
    for ( l = list_begin (&t->files); l != list_end (&t->files); l = list_next (l))
    {
        ret = list_entry (l, struct fd_elem, thread_elem);
        if (ret->fd == fd)
            return ret;
    }
    
    return NULL;
}