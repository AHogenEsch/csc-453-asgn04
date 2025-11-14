#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <minix/const.h> // R_BIT and W_BIT
#include <sys/ioc_secret.h> // SSGRANT definition
#include <sys/ucred.h> // struct ucred
#include <minix/syslib.h> // sys_getnucred
#include <sys/types.h>
#include "secret.h"

// MANUAL DEFINITIONS, the compiler was not seeing the correct headers
typedef unsigned int devminor_t;
typedef unsigned int cdev_id_t;
/*
 * Function prototypes for the secret driver.
 */
static int secret_open(devminor_t minor, int access, endpoint_t user_endpt);
static int secret_close(devminor_t minor);
static ssize_t secret_read(devminor_t minor, u64_t position, endpoint_t endpt,
    cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);
static ssize_t secret_write(devminor_t minor, u64_t position, endpoint_t endpt,
    cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);
static int secret_ioctl(devminor_t minor, 
    unsigned long request, endpoint_t endpt, cp_grant_id_t grant, 
    int flags, endpoint_t user_endpt, cdev_id_t id);

// Helper function to reset the secret state
static void secret_reset(void);
 
/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
static int sef_cb_lu_state_save(int, int);
static int lu_state_restore(void);
 
/* Entry points to the secret driver. */
static struct chardriver secret_tab =
{
    .cdr_open = secret_open,
    .cdr_close = secret_close,
    .cdr_read = secret_read,
    .cdr_write = secret_write,
    .cdr_ioctl = secret_ioctl,
};
 /** State variable to count the number of times the device has been opened.
 * Note that this is not the regular type of open counter: it never decreases.
 */

static int open_counter;


// Variables:
// The secret data buffer itself.
static char secret_data[SECRET_SIZE];

// The UID of the current owner of the secret. 
// A value of NO_OWNER_UID indicates no owner.
static uid_t secret_owner = NO_OWNER_UID;
// Current size of the secret data (number of bytes written).
static size_t secret_len = 0;

// The current number of open file descriptors for this device.
static int open_count = 0;

/* Flag to track if a read file descriptor 
 * has ever been opened since the last secret write/reset. 
 */
static int read_fd_opened_since_write = FALSE;

/*
 * Resets the state of the secret device (clears data, removes owner).
 */
static void secret_reset(void)
{
    secret_owner = NO_OWNER_UID;
    secret_len = 0;
    read_fd_opened_since_write = FALSE;
    memset(secret_data, 0, SECRET_SIZE); 
}


// --- Driver Function Implementations ---

static int secret_open(devminor_t UNUSED(minor), int access,
    endpoint_t user_endpt)
{
    int r;
    struct ucred ucred;
    uid_t caller_uid;

    // Get the credentials of the calling process
    r = sys_getnucred(user_endpt, &ucred);
    if (r != OK) return r;
    caller_uid = ucred.uid;

    // Increment the total open count (for monitoring, not for device logic)
    open_counter++;
    // Increment the file descriptor count
    open_count++;

    // Check for Read-Write access (O_RDWR is R_BIT | W_BIT, value 6)
    if ((access & (R_BIT | W_BIT)) == (R_BIT | W_BIT)) {
         // The device may not be opened for read-write access (EACCES) 
        open_count--;
        return EACCES;
    }

    // Check if device is full (owned by somebody)
     if (secret_owner != NO_OWNER_UID) { // Full 
        if (access & W_BIT) {
             // May not be opened for writing once it is holding a secret
             // Attempts to open a full secret for writing result in ENOSPC
            open_count--;
            return ENOSPC;
        }

        if (access & R_BIT) {
    // May be opened for reading by a process owned by the owner of the secret
            if (caller_uid == secret_owner) {
            // Keep track of the fact that a read descriptor has been opened.
                read_fd_opened_since_write = TRUE;  // Used for close logic
                return OK;
            } else {
    // Attempts to read a secret belonging to another user result in EACCES
                open_count--;
                return EACCES;
            }
        }
        
        // Should be covered, but defensively close open_count
        open_count--;
        return EACCES;

     } else { // Empty (owned by nobody)

        if (access & W_BIT) {
    // Open for writing can only succeed if the secret is not owned by anybody.
        // This means it may only be opened for writing once. 
        // The owner of that process will then become the owner of the secret.
            secret_owner = caller_uid;
// The secret is "full" now, preventing new opens for writing until reset.
            return OK;
        }

        if (access & R_BIT) {
             /* Any process may open /dev/Secret for reading 
              * That owner of that process will then become the owner 
              * of the secret (determined via getnucred(2))
              */
            secret_owner = caller_uid;
            /*  Note: Unlike a successful write, a read open when empty
             * does *not* set the secret_len, so it's "owned" but logically
             * "empty" (secret_len=0). It can still be written to by the owner.
             */
            read_fd_opened_since_write = TRUE; 
        // Even if empty, a read fd is opened. This sets up for close logic.
            return OK;
        }
        
    // This case should not be reachable for a valid open with R or W bit set
        open_count--;
        return EACCES;
    }
}

static int secret_close(devminor_t UNUSED(minor))
{
    // Decrement the file descriptor count
    if (open_count > 0) {
        open_count--;
    }

    /* Closing: when the last file descriptor is closed after any read file
     * descriptor has been opened, /dev/Secret reverts to being empty.
     * The secret resets when the last file descriptor closes *after* a 
     * read file descriptor has been opened.
     */
    if (open_count == 0 && read_fd_opened_since_write == TRUE) {
        secret_reset();
    }
    
    return OK;
}
static ssize_t secret_read(devminor_t UNUSED(minor), u64_t position,
    endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
    cdev_id_t UNUSED(id))
{
    // Check if a secret exists to read
    if (secret_owner == NO_OWNER_UID || secret_len == 0) {
        /* While the secret owner might be set by a read-open, 
         * if secret_len is 0, there's nothing to read.
         */
        return 0; // EOF if no data written
    }

    // Get the credentials of the calling process for permission check
    struct ucred ucred;
    uid_t caller_uid;
    int r = sys_getnucred(endpt, &ucred);
    if (r != OK) return r;
    caller_uid = ucred.uid;

     // Attempts to read a secret belonging to another user result in EACCES.
    if (caller_uid != secret_owner) {
        return EACCES;
    }

    // Check for EOF or limit read size
    if (position >= secret_len) return 0; /* EOF: read beyond written data */
    if (position + size > secret_len) /* Limit read to available data */
        size = (size_t)(secret_len - (size_t)position); 

    // Copy the requested part to the caller's buffer.
    char *ptr = secret_data + (size_t)position;
    if ((r = sys_safecopyto(endpt, grant, 0, (vir_bytes) ptr, size)) != OK)
        return r;

    // Return the number of bytes read.
    return size;
}

static ssize_t secret_write(devminor_t UNUSED(minor), u64_t position,
    endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
    cdev_id_t UNUSED(id))
{
    /* The device only allows one write, and only when not full/owned.
     * The permission check logic should largely be in open(), 
     * but we re-check for safety. If position is not 0, something is wrong
     *  as this device is not seekable.
     */ 
    if (position != 0) {
        /* Since the device is not seekable, any non-zero position indicates
         * a logic error or a write that should be treated as a new write,
         * but a new write shouldn't happen if the device is already
         * logically "full" (owner set). Let's rely on the open check for
         * ownership. If open was successful for write, it means we are
         * either the first writer or the owner is set to us and we're writing
         * to an empty secret (secret_len == 0) but the owner is set.
         */ 
    }
    
     // Check if the write operation fits within the buffer size.
    if (size > SECRET_SIZE) {
        return ENOSPC;
    }
    
    /* Check if the current secret is already written (secret_len > 0), 
     * a new write shouldn't be allowed. Since open for write is only allowed
     * once (and sets the owner), the logic is:
     * 1. Secret owner must be set (from the open call)
     * 2. Secret length must be 0 (meaning this is the first successful write)
     */
    if (secret_len > 0) {
        /* This case indicates a subsequent write attempt after a successful
         * initial write. This should not happen if the open logic is correct
         * (only one write open allowed). If it does, we return ENOSPC, as 
         * the device is logically "full."
         */ 
        return ENOSPC;
    }

    // Copy data from the caller's buffer into the device's secret_data buffer.
    int r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes) secret_data, size);
    if (r != OK) {
        return r;
    }

    // Update the secret length and reset the read_fd_opened_since_write 
    // flag since a new secret is written.
    secret_len = size;
    // A new write should reset the closure flag state
    read_fd_opened_since_write = FALSE; 

    // Return the number of bytes written.
    return size;
}

static int secret_ioctl(devminor_t UNUSED(minor), unsigned long request, 
    endpoint_t endpt, cp_grant_id_t grant, int UNUSED(flags), 
    endpoint_t UNUSED(user_endpt), cdev_id_t UNUSED(id))
{
     // Check for the single supported ioctl call, SSGRANT.
    if (request == SSGRANT) {
        uid_t grantee;
        struct ucred ucred;
        uid_t caller_uid;
        int r;

         // Get the credentials of the calling process.
        r = sys_getnucred(endpt, &ucred);
        if (r != OK) return r;
        caller_uid = ucred.uid;

        // Only the current owner of a secret can change the ownership.
        if (caller_uid != secret_owner) {
            return EACCES; // Permission denied if not the owner
        }

// Get the parameter (the new owner's UID) from the caller's address space.
        r = sys_safecopyfrom(endpt, grant, 0, 
            (vir_bytes) &grantee, sizeof(grantee));
        if (r != OK) {
            return r;
        }

        // Change the ownership to the new user.
        secret_owner = grantee;

        return OK;
    }
    
     // Any ioctl(2) requests other than SSGRANT get a ENOTTY response.
    return ENOTTY;
}

// --- Live Update (LU) Functions---

static int sef_cb_lu_state_save(int UNUSED(state), int UNUSED(flags)) {
    int r;
    
    // Save the general open counter 
    ds_publish_u32("open_counter", open_counter, DSF_OVERWRITE);
    
     // Save device state variables
    ds_publish_u32("secret_owner", secret_owner, DSF_OVERWRITE);
    ds_publish_u32("secret_len", (u32_t) secret_len, DSF_OVERWRITE);
    ds_publish_u32("read_fd_opened_since_write", 
        read_fd_opened_since_write, DSF_OVERWRITE);
    ds_publish_u32("open_count", open_count, DSF_OVERWRITE);

     // Save the secret data itself
    if (secret_len > 0) {
        // Only publish the portion that has been written
        if ((r = ds_publish_mem("secret_data", secret_data, secret_len,
            DSF_OVERWRITE)) != OK) {
            return r;
        }
    }
    
    return OK;
}

static int lu_state_restore() {
    u32_t value_u32;
    size_t length;
    int r;
    
    // Restore open_counter
    ds_retrieve_u32("open_counter", &value_u32);
    ds_delete_u32("open_counter");
    open_counter = (int) value_u32;
    
    // Restore device state variables
    ds_retrieve_u32("secret_owner", &value_u32);
    ds_delete_u32("secret_owner");
    secret_owner = (uid_t) value_u32;
    
    ds_retrieve_u32("secret_len", &value_u32);
    ds_delete_u32("secret_len");
    secret_len = (size_t) value_u32;

    ds_retrieve_u32("read_fd_opened_since_write", &value_u32);
    ds_delete_u32("read_fd_opened_since_write");
    read_fd_opened_since_write = (int) value_u32;

    ds_retrieve_u32("open_count", &value_u32);
    ds_delete_u32("open_count");
    open_count = (int) value_u32;
    
    // Restore the secret data
    if (secret_len > 0) {
        length = secret_len;
        if ((r = ds_retrieve_mem("secret_data", secret_data, &length)) != OK) {
            return r;
        }
        ds_delete_mem("secret_data");
        // Re-check: If length is less than original secret_len,
        //  we have a problem, but for now, assume retrieve was complete.
    }
    
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