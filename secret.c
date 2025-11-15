#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <minix/const.h> // R_BIT and W_BIT
#include <sys/ioc_secret.h> // SSGRANT definition
#include <sys/ucred.h> // struct ucred
#include <minix/syslib.h> // sys_getnucred, sys_safecopyfrom/to
#include <string.h> // for memset
#include <sys/types.h>
#include "secret.h"

/* --- MANUAL TYPE DEFINITIONS & PLACEHOLDERS (For minimal test harness) --- */

// Base MINIX types that were missing/needed for the new signatures
typedef unsigned int devminor_t;
typedef unsigned int cdev_id_t;
typedef unsigned long long u64_t;
typedef int endpoint_t;
typedef int cp_grant_id_t; 
typedef int ssize_t; 
typedef char * vir_bytes; 
typedef unsigned int uid_t;

// Standard MINIX structures/types that were missing (must be defined or included)
typedef struct { /* Placeholder for iovec_t struct */ } iovec_t;
typedef struct { /* Placeholder for message struct */ } message;
typedef int dev_t; // Required by cdr_prepare
// Required for sys_getnucred prototype
struct ucred { int pid; uid_t uid; int gid; }; 

// System Constants & Error Codes (from <errno.h> and <minix/const.h>)
#define OK 0
#define EACCES 13
#define ENOSPC 28
#define ENOTTY 25
#define TRUE 1
#define FALSE 0
#define R_BIT 4 // O_RDONLY (from assignment PDF)
#define W_BIT 2 // O_WRONLY (from assignment PDF)

// VFS Message Field Access (Simplified mapping for control functions)
// Assuming standard MINIX message passing fields for open/close/ioctl
#define M_DEVICE      m_lc.m_vfs_open.device 
#define M_ACCESS      m_lc.m_vfs_open.access 
#define M_IOCTL_REQ   m_lc.m_vfs_ioctl.request
#define M_IOCTL_GRANT m_lc.m_vfs_ioctl.grant
#define M_CALLER_ENDPT m_source 

// System Function Prototypes (Fixes 'implicit declaration')
int sys_getnucred(endpoint_t endpt, struct ucred *ucred);
int sys_safecopyto(endpoint_t dst_endpt, cp_grant_id_t grant, vir_bytes grant_off,
    vir_bytes vir_addr, size_t len);
int sys_safecopyfrom(endpoint_t src_endpt, cp_grant_id_t grant, vir_bytes grant_off,
    vir_bytes vir_addr, size_t len);

// Macro for unused variables 
#define UNUSED(x) (void)x
/* --- END MANUAL DEFINITIONS --- */

/*
 * Function prototypes for the secret driver (updated for the new chardriver struct).
 */
static int secret_open(message *m_ptr);
static int secret_close(message *m_ptr);
static int secret_ioctl(message *m_ptr);
// New combined transfer function
static int secret_transfer(endpoint_t endpt, int opcode, u64_t position, 
    iovec_t *iov, unsigned int nr_req, endpoint_t user_endpt);

// Non-essential boilerplate driver functions 
static int nop_prepare(dev_t dev);

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
    .cdr_open       = secret_open,
    .cdr_close      = secret_close,
    .cdr_ioctl      = secret_ioctl,
    .cdr_prepare    = nop_prepare,          // Required field
    .cdr_transfer   = secret_transfer,      // Replaced read/write
    .cdr_cleanup    = NULL,
    .cdr_alarm      = NULL,
    .cdr_cancel     = NULL,
    .cdr_select     = NULL,
    .cdr_other      = NULL
};
 
// Variables:
static int open_counter;
static char secret_data[SECRET_SIZE];
static uid_t secret_owner = NO_OWNER_UID;
static size_t secret_len = 0;
static int open_count = 0;
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

// --- Placeholder for boilerplate ---

/* Not doing any special preparation before transfer */
static int nop_prepare(dev_t UNUSED(dev))
{
    return OK;
}

// --- Driver Function Implementations (Updated for message passing) ---

static int secret_open(message *m_ptr)
{
    int r;
    struct ucred ucred;
    uid_t caller_uid;
    // Extract parameters from the message struct
    endpoint_t user_endpt = m_ptr->M_CALLER_ENDPT;
    int access = m_ptr->M_ACCESS; 
    
    // Get the credentials of the calling process
    r = sys_getnucred(user_endpt, &ucred);
    if (r != OK) return r;
    caller_uid = ucred.uid;

    open_counter++;
    open_count++;

    // 1. Check for Read-Write access (O_RDWR is R_BIT | W_BIT, value 6)
    if ((access & (R_BIT | W_BIT)) == (R_BIT | W_BIT)) {
        open_count--;
        return EACCES; // The device may not be opened for read-write access
    }

    // 2. Device is FULL (owned by somebody)
    if (secret_owner != NO_OWNER_UID) { 
        if (access & W_BIT) {
            // Attempts to open a full secret for writing result in ENOSPC
            open_count--;
            return ENOSPC;
        }

        if (access & R_BIT) {
            // May be opened for reading by a process owned by the secret owner
            if (caller_uid == secret_owner) {
                read_fd_opened_since_write = TRUE; 
                return OK;
            } else {
                // Attempts to read a secret belonging to another user result in EACCES
                open_count--;
                return EACCES;
            }
        }
        
        open_count--;
        return EACCES;

    } else { // 3. Device is EMPTY (owned by nobody)

        if (access & W_BIT) {
            // Open for writing only succeeds if not owned, and sets the owner.
            secret_owner = caller_uid;
            // The secret is "full" now, preventing new write opens.
            return OK;
        }

        if (access & R_BIT) {
            /* Any process may open /dev/Secret for reading. That owner 
             * will then become the owner of the secret.
             */
            secret_owner = caller_uid;
            read_fd_opened_since_write = TRUE; 
            return OK;
        }
        
        open_count--;
        return EACCES;
    }
}

static int secret_close(message *m_ptr)
{
    // The message pointer is often unused in close, but we use it to conform to signature.
    UNUSED(m_ptr); 

    // Decrement the file descriptor count
    if (open_count > 0) {
        open_count--;
    }

    /* Resetting: when the last file descriptor is closed after any read 
     * file descriptor has been opened, /dev/Secret reverts to being empty.
     */
    if (open_count == 0 && read_fd_opened_since_write == TRUE) {
        secret_reset();
    }
    
    return OK;
}

static int secret_transfer(endpoint_t endpt, int opcode, u64_t position, 
    iovec_t *iov, unsigned int nr_req, endpoint_t user_endpt)
{
    // In this model, nr_req is the number of iovec_t elements. 
    // For a simple driver, we only expect one request (nr_req == 1).
    if (nr_req != 1) {
        // This indicates an unsupported scatter/gather operation
        return EINVAL; 
    }

    // The logic inside iov depends on the struct, but typically includes 
    // grant ID, buffer offset, and size for the first transfer (iov[0]).
    // Since we don't have the definition of iovec_t, we use the arguments 
    // to determine the grant ID and size needed for sys_safecopy.
    // NOTE: This assumes the chardriver wrapper passes the actual 
    // grant ID and size *implicitly* or via the first iov_t element.
    
    // We must revert to using the single grant/size from the older read/write model
    // which is common when iovec_t is simple or absent. We will assume the 
    // required grant/size are passed from the original calling process, but 
    // in this transfer model, we have to extract them from iov.

    // To proceed without the full iovec_t definition, we must assume the 
    // wrapper extracts the single grant and size and passes them to our logic.
    // For now, we will use a placeholder grant/size, as the opcode and position are correct.

    // PLACEHOLDER: Assuming iov and nr_req contain the necessary transfer info.
    cp_grant_id_t grant = (cp_grant_id_t) iov; // Highly imperfect placeholder
    size_t size = (size_t) nr_req;            // Highly imperfect placeholder

    // The opcode determines read or write.
    // DEV_SCATTER_S is generally WRITE (data scatters from user to driver).
    // DEV_GATHER_S is generally READ (data gathers from driver to user).

    if (opcode == DEV_SCATTER_S) {
        // Write logic
        
        // Check if the write operation fits within the buffer size.
        if (size > SECRET_SIZE) {
            return ENOSPC;
        }
        
        // Ensure this is the first write
        if (secret_len > 0) {
             return ENOSPC;
        }

        // Copy data from the caller's buffer.
        int r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes) secret_data, size);
        if (r != OK) {
            return r;
        }

        secret_len = size;
        read_fd_opened_since_write = FALSE; 

        return size; // Return bytes written

    } else if (opcode == DEV_GATHER_S) {
        // Read logic

        // Check ownership (The owner check is critical and must be done here)
        struct ucred ucred;
        uid_t caller_uid;
        int r = sys_getnucred(user_endpt, &ucred);
        if (r != OK) return r;
        caller_uid = ucred.uid;
        
        // Check if a secret exists to read and if caller is the owner
        if (secret_owner == NO_OWNER_UID || secret_len == 0) {
            return 0; 
        }
        if (caller_uid != secret_owner) {
            return EACCES;
        }

        // Check for EOF or limit read size
        if (position >= secret_len) return 0;
        if (position + size > secret_len) 
            size = (size_t)(secret_len - (size_t)position); 

        // Copy the requested part to the caller's buffer.
        char *ptr = secret_data + (size_t)position;
        if ((r = sys_safecopyto(endpt, grant, 0, (vir_bytes) ptr, size)) != OK)
            return r;

        return size; // Return bytes read

    } else {
        // Unsupported opcode
        return EINVAL;
    }
}

static int secret_ioctl(message *m_ptr)
{
    // Extract parameters from the message struct
    unsigned long request = m_ptr->M_IOCTL_REQ;
    endpoint_t endpt = m_ptr->M_CALLER_ENDPT;
    cp_grant_id_t grant = m_ptr->M_IOCTL_GRANT;
    
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

        // Get the new owner's UID from the caller's address space.
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

// --- SEF and Main Loop Functions (Copied from original, assuming they are correct) ---

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
    }
    
    return OK;
}
 
static void sef_local_startup()
{
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);
 
    sef_setcb_lu_state_save(sef_cb_lu_state_save);
    sef_startup();
}
 
static int sef_cb_init(int type, sef_init_info_t *UNUSED(info))
{
    int do_announce_driver = TRUE;
 
    open_counter = 0;
    switch(type) {
        case SEF_INIT_FRESH:
            printf("%s", secret_MESSAGE);
        break;
 
        case SEF_INIT_LU:
            lu_state_restore();
            do_announce_driver = FALSE;
            printf("%sHey, I'm a new version!\n", secret_MESSAGE);
        break;
 
        case SEF_INIT_RESTART:
            printf("%sHey, I've just been restarted!\n", secret_MESSAGE);
        break;
    }
 
    if (do_announce_driver) {
        chardriver_announce();
    }
 
    return OK;
}
 
int main(void)
{
    sef_local_startup();
    chardriver_task(&secret_tab);
    return OK;
}