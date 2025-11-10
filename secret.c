#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include "secret.h"
 
/*
 * Function prototypes for the secret driver.
 */
static int secret_open(devminor_t minor, int access, endpoint_t user_endpt);
static int secret_close(devminor_t minor);
static ssize_t secret_read(devminor_t minor, u64_t position, endpoint_t endpt,
    cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);
 
/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
static int sef_cb_lu_state_save(int, int);
static int lu_state_restore(void);
 
/* Entry points to the secret driver. */
static struct chardriver secret_tab =
{
    .cdr_open	= secret_open,
    .cdr_close	= secret_close,
    .cdr_read	= secret_read,
};
 /** State variable to count the number of times the device has been opened.
 * Note that this is not the regular type of open counter: it never decreases.
 */

static int open_counter;

/* General Behaviour:
    • The secret held by /dev/Secret may be of fixed size. Exactly how big doesn’t matter, but
    it should be settable by defining the macro SECRET SIZE in your driver’s source. Attempts to
    write more into the device than will fit will result in an ENOSPC response.
    The test harness will expect your buffer size to be 8192 (8KB), but, of course, this should
    be configurable by changing a SECRET SIZE. To make it reconfigureable while compiling (do),
    define it 

    • /dev/Secret supports a single ioctl(2) call, SSGRANT, which allows the owner of a secret to
    change the ownership to another user. E.g.:
    ioctl(fd, SSGRANT, &other uid);
    Any ioctl(2) requests other than SSGRANT get a ENOTTY response.
    • /dev/Secret should preserve its state over live update events.

    Do be careful not to allow a process to write beyond the end of the secret buffer, nor to read
        beyond what has been written. Be aware that a process may read or write many times so you
        will have to keep track of where the last read or write occurred.
*/

// Variables:
// static owner = NULL
static int isFull = 0; // 1 is full
//static lastRead = NULL




static int secret_open(devminor_t UNUSED(minor), int UNUSED(access),
    endpoint_t UNUSED(user_endpt))
{
    /*
The flags given to open() are passed along in the DEV OPEN message in the COUNT field.
    These flags are not the same as the ones defined in fcntl.h. They have been re-mapped by
    the filesystem to be the same as the bits used in the file permissions mode. These values are
    defined in <minix/const.h>:
    #define R BIT 0000004 // Rwx protection bit 
    #define W BIT 0000002 // rWx protection bit 
    This means that our usual flag sets will have the following values:
    O WRONLY 2
    O RDONLY 4
    O RDWR 6
    4
    Of course there may be other flags as well. This is a bitfield that encodes all the flags passed
    to open(2)
*/
    if(isFull){
    /* If full (owned by somebody):
        – /dev/Secret may not be opened for writing once it is holding a secret.
        – /dev/Secret may be opened for reading by a process owned by the owner of the secret.
        You must keep track of how many open file descriptors there are, however, because the
        secret resets when the last file descriptor closes after a read file descriptor has been
        opened1
        .
        – Attempts to open a full secret for writing result in a device full error (ENOSPC).
        – Attempts to read a secret belonging to another user result in a permission denied error
        (EACCES).
    */

    /*
        To determine the owner of the process calling open(2) (the only place you care about ownership) 
        you can use getnucred(2) to populate a struct ucred, defined in include/sys/ucred.h
            to be:
            struct ucred {
            pid t pid;
            uid t uid;
            gid t gid;
            };              
    */
    }
    else{
    /* If empty (owned by nobody):
        – Any process may open /dev/Secret for reading or writing.
        – That owner of that process will then become the owner of the secret. (determined via
        getnucred(2))
        – Open for writing can only succeed if the secret is not owned by anybody. This means it
        may only be opened for writing once.
        – The device may not be opened for read-write access (because it makes no sense). This
        results in a permission denied error (EACCES).
    */        
    }

/* Data transfer. Hello only demonstrates transfer out of the device, but transfer in is analogous.
        The functions you’re interested in are sys safecopyfrom() and sys safecopyto() to copy
        from and to another process respectively.
    As seen in the hello driver, the opcode for reading is DEV GATHER S. The opcode for writing is
        DEV SCATTER S.
    Because this is a character device, feel free to ignore the position parameter. /dev/Secret
        isn’t seekable and the reader/writer gets whatever’s next.
    Do be careful not to allow a process to write beyond the end of the secret buffer, nor to read
        beyond what has been written. Be aware that a process may read or write many times so you
        will have to keep track of where the last read or write occurred.
*/




    printf("secret_open(). Called %d time(s).\n", ++open_counter);
    return OK;
}
 

/* Close Requirements
 Closing: when the last file descriptor is closed after any read file descriptor has been opened,
/dev/Secret reverts to being empty
*/
static int secret_close(devminor_t UNUSED(minor))
{
    printf("secret_close()\n");
    return OK;
}
 
static ssize_t secret_read(devminor_t UNUSED(minor), u64_t position,
    endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
    cdev_id_t UNUSED(id))
{
    /* – Attempts to read a secret belonging to another user result in a permission denied error
    (EACCES).

    – If Empty: The device may not be opened for read-write access (because it makes no sense). This
    results in a permission denied error (EACCES).

    Do be careful not to allow a process to write beyond the end of the secret buffer, nor to read
        beyond what has been written. Be aware that a process may read or write many times so you
        will have to keep track of where the last read or write occurred.

    */
   if(!isFull){
    return EACCES;
   }

   /* • Note: Nothing says that the secret is a string. Beware any of libc’s string functions. They
    may not do what you want. */
    u64_t dev_size;
    char *ptr;
    int ret;
    char *buf = secret_MESSAGE;
 
    printf("secret_read()\n");
 
    /* This is the total size of our device. */
    dev_size = (u64_t) strlen(buf);
 
    /* Check for EOF, and possibly limit the read size. */
    if (position >= dev_size) return 0;		/* EOF */
    if (position + size > dev_size)
        size = (size_t)(dev_size - position);	/* limit size */
 
    /* Copy the requested part to the caller. */
    ptr = buf + (size_t)position;
    if ((ret = sys_safecopyto(endpt, grant, 0, (vir_bytes) ptr, size)) != OK)
        return ret;
 
    /* Return the number of bytes read. */
    return size;
}
 
static int sef_cb_lu_state_save(int UNUSED(state), int UNUSED(flags)) {
/* Save the state. */
    ds_publish_u32("open_counter", open_counter, DSF_OVERWRITE);
 
    return OK;
}
 
static int lu_state_restore() {
/* Restore the state. */
    u32_t value;
 
    ds_retrieve_u32("open_counter", &value);
    ds_delete_u32("open_counter");
    open_counter = (int) value;
 
    return OK;
}
 
static void sef_local_startup()
{
    /*
     * Register init callbacks. Use the same function for all event types
     */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);
 
    /*
     * Register live update callbacks.
     */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);
 
    /* Let SEF perform startup. */
    sef_startup();
}
 
static int sef_cb_init(int type, sef_init_info_t *UNUSED(info))
{
/* Initialize the secret driver. */
    int do_announce_driver = TRUE;
 
    open_counter = 0;
    switch(type) {
        case SEF_INIT_FRESH:
            printf("%s", secret_MESSAGE);
        break;
 
        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;
 
            printf("%sHey, I'm a new version!\n", secret_MESSAGE);
        break;
 
        case SEF_INIT_RESTART:
            printf("%sHey, I've just been restarted!\n", secret_MESSAGE);
        break;
    }
 
    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        chardriver_announce();
    }
 
    /* Initialization completed successfully. */
    return OK;
}
 
int main(void)
{
    /*
     * Perform initialization.
     */
    sef_local_startup();
 
    /*
     * Run the main loop.
     */
    chardriver_task(&secret_tab);
    return OK;
}