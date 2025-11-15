#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <minix/const.h> // R_BIT and W_BIT
#include <sys/ioc_secret.h> // SSGRANT definition
#include <sys/ucred.h> // struct ucred
#include <minix/syslib.h> // sys_getnucred, sys_safecopyfrom/to
#include <sys/types.h>

#include "secret.h" // For SECRET_SIZE

// --- Fixes for Missing Constants and Prototypes ---

// 1. Manual definitions for missing SEF/Signal constants
#define SIGTERM 15
#define SEF_OTHER_SIGNAL 1

// 2. Manual definitions for missing chardriver transfer constants
#define DEV_READ 1
#define DEV_WRITE 2

// 3. Manual definition for chardriver task type
#define CD_DEV 0

// 4. Manual definition for the missing IOCTL constant SSREVOKE
#ifndef SSREVOKE
#define SSREVOKE _IOC(1, 'S', 2)
#endif

// 5. Manual typedefs to resolve 'unknown type name' errors
typedef unsigned int devminor_t;
typedef unsigned int cdev_id_t;

// --- Implicit Function Prototypes (to resolve implicit declaration warnings) ---
endpoint_t chardriver_get_caller_endpt(void);
void chardriver_terminate(void);
void sef_setcb_signal_handler(int (*handler)(int));
void sef_dev_set_name(const char *name);
void sef_init(int (*cb_init)(int, sef_init_info_t *));
void sef_setcb_lu_state_save(void (*handler)(int, int));
int sys_getnucred(endpoint_t proc_ep, struct ucred *ucred_ptr); // Fix for implicit declaration of sys_getnucred
int get_endpoint_by_uid(uid_t uid, endpoint_t *endpt); // Dummy prototype for compilation

// --- Device State ---
static char secret_data[SECRET_SIZE];
static size_t secret_len = 0;
static endpoint_t secret_owner = 0; // 0 is equivalent to NONE
static endpoint_t secret_reader = 0;

// --- Function Prototypes for the character driver table ---
struct device *nop_prepare(int device);
static void secret_cleanup(int minor);
static int secret_open(devminor_t minor, int flags);
static int secret_close(devminor_t minor);
static int secret_ioctl(devminor_t minor, unsigned long request, endpoint_t user_endpt, cp_grant_id_t grant);
// cdr_transfer replaces cdr_read and cdr_write in the chardriver struct
static ssize_t secret_transfer(devminor_t minor, int operation, endpoint_t user_endpt,
    cp_grant_id_t grant, size_t pos, size_t num_bytes, int flags);

// --- SEF function prototypes ---
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
static void sef_cb_lu_state_save(int state, int flags);
static int sef_cb_signal_handler(int signo);

/* Character driver entry points */
static struct chardriver secret_tab =
{
    .cdr_prepare = nop_prepare,
    .cdr_cleanup = secret_cleanup,
    .cdr_open = secret_open,
    .cdr_close = secret_close,
    .cdr_ioctl = secret_ioctl,
    // Fix: Use cdr_transfer to handle both read and write operations
    .cdr_transfer = secret_transfer,
};


/* No-op function for prepare */
struct device *nop_prepare(int device)
{
    static struct device dev;
    UNUSED(device);
    return &dev;
}

/* Cleanup function */
static void secret_cleanup(int minor)
{
    UNUSED(minor);
}

/* Helper function to get the current user's UID */
static uid_t get_caller_uid(endpoint_t user_endpt)
{
    struct ucred ucred;
    // Use sys_getnucred, prototyped above, to match compiler warning
    if (sys_getnucred(user_endpt, &ucred) != OK) {
        // If sys_getnucred fails, return an invalid UID
        return (uid_t)-1;
    }
    return ucred.uid;
}

/* Helper function to get the current user's endpoint */
static endpoint_t get_caller_endpt(void)
{
    return chardriver_get_caller_endpt();
}


/* Open routine */
static int secret_open(devminor_t minor, int flags)
{
    endpoint_t user_endpt;

    UNUSED(minor);

    user_endpt = get_caller_endpt();

    [cite_start]// Deny read-write access (R_BIT | W_BIT == 6) [cite: 297, 298]
    if ((flags & (R_BIT | W_BIT)) == (R_BIT | W_BIT)) {
        return EACCES;
    }

    // Case 1: Device is empty (owned by nobody)
    if (secret_owner == 0) {
        [cite_start]// Any open (R or W) on an empty device makes the process owner [cite: 293, 294]
        if (flags & (W_BIT | R_BIT)) {
            secret_owner = user_endpt;
            return OK;
        }
        return EACCES;
    }

    // Case 2: Device is full (owned by somebody)
    if (secret_owner != 0) {
        [cite_start]// Deny write access [cite: 300]
        if (flags & W_BIT) {
            // Note: Assignment implies ENOSPC for attempts to write when full,
            // but the open(W) operation itself should be EACCES or ENOSPC.
            // Returning EACCES for the open check as it's a permission issue
            // based on ownership/state, and ENOSPC can be for the transfer.
            return EACCES;
        }

        [cite_start]// Allow read access only if the user is the owner or the granted reader [cite: 301]
        if (flags & R_BIT) {
            if (user_endpt == secret_owner || user_endpt == secret_reader) {
                return OK;
            } else {
                [cite_start]// Deny read access to all others [cite: 304]
                return EACCES;
            }
        }
    }

    return EACCES;
}

/* Close routine */
static int secret_close(devminor_t minor)
{
    endpoint_t user_endpt;

    UNUSED(minor);

    user_endpt = get_caller_endpt();

    // If the owner is closing, clear the secret and ownership.
    [cite_start]// This is the simplest interpretation of the reset logic [cite: 307]
    if (user_endpt == secret_owner) {
        secret_owner = 0;
        secret_reader = 0;
        secret_len = 0;
    }
    // A reader closing their FD does not clear the grant/secret.

    return OK;
}

/* Read/Write transfer routine (cdr_transfer) */
static ssize_t secret_transfer(devminor_t minor, int operation, endpoint_t user_endpt,
    cp_grant_id_t grant, size_t pos, size_t num_bytes, int flags)
{
    ssize_t bytes_transferred = 0;

    UNUSED(minor);
    UNUSED(flags);

    if (secret_owner == 0) {
        return EACCES;
    }

    if (operation == DEV_READ) {
        // Check read permission
        if (user_endpt != secret_owner && user_endpt != secret_reader) {
            return EACCES;
        }

        // Handle bounds check
        if (pos >= secret_len) {
            return 0; // EOF
        }
        if (pos + num_bytes > secret_len) {
            num_bytes = secret_len - pos;
        }

        // Copy to user process. The final argument must be 0 for 'flags' in this context.
        if (sys_safecopyto(user_endpt, grant, 0,
            (vir_bytes)(secret_data + pos), num_bytes, 0) != OK) {
            return EIO;
        }

        bytes_transferred = num_bytes;

    } else if (operation == DEV_WRITE) {
        // Check write permission (only owner can write)
        if (user_endpt != secret_owner) {
            return EACCES;
        }

        // Handle bounds check (cannot write beyond SECRET_SIZE)
        if (pos + num_bytes > SECRET_SIZE) {
            if (pos >= SECRET_SIZE) {
                return ENOSPC;
            }
            num_bytes = SECRET_SIZE - pos;
            bytes_transferred = ENOSPC; // Indicate error if truncation occurred
        }

        // Copy from user process. The final argument must be 0 for 'flags' in this context.
        if (sys_safecopyfrom(user_endpt, grant, 0,
            (vir_bytes)(secret_data + pos), num_bytes, 0) != OK) {
            return EIO;
        }

        // Update the current length of the secret
        if (pos + num_bytes > secret_len) {
            secret_len = pos + num_bytes;
        }

        bytes_transferred = num_bytes;
    }

    return bytes_transferred;
}

/* IOCTL routine */
static int secret_ioctl(devminor_t minor, unsigned long request, endpoint_t user_endpt, cp_grant_id_t grant)
{
    int r;
    uid_t target_uid;
    endpoint_t target_endpt;

    UNUSED(minor);

    // Only the owner of the secret can perform IOCTLs
    if (user_endpt != secret_owner) {
        return EPERM;
    }

    switch (request) {
        case SSGRANT: {
            [cite_start]// Owner grants read permission to a target UID[cite: 314].
            size_t size = sizeof(target_uid);

            // Copy the target UID from the user process via grant
            if (sys_safecopyfrom(user_endpt, grant, 0, (vir_bytes)&target_uid, size, 0) != OK) {
                return EFAULT;
            }

            // Find the endpoint corresponding to the target UID
            r = get_endpoint_by_uid(target_uid, &target_endpt);

            if (r != OK) {
                return ESRCH; // No such process/user
            }

            // Set the new reader endpoint
            secret_reader = target_endpt;

            return OK;
        }

        case SSREVOKE: {
            // Revoke read permission (SSREVOKE is manually defined)
            secret_reader = 0;
            return OK;
        }

        default:
            return ENOTTY; [cite_start]// Any ioctl requests other than SSGRANT/SSREVOKE [cite: 317]
    }
}


/* SEF Callbacks for Live Update (LU) */

static void sef_cb_lu_state_save(int state, int flags)
{
    UNUSED(state);
    UNUSED(flags);

    // Save state variables
    ds_publish_u32("secret_owner", secret_owner, 0);
    ds_publish_u32("secret_reader", secret_reader, 0);
    ds_publish_u32("secret_len", (u32_t)secret_len, 0);
}

static int sef_cb_init(int type, sef_init_info_t *info)
{
    UNUSED(info);

    if (type == SEF_INIT_FRESH) {
        // Fresh start: initialize state
        secret_owner = 0;
        secret_reader = 0;
        secret_len = 0;
    } else if (type == SEF_INIT_LU) {
        // Live Update: retrieve state
        u32_t val;
        int r;

        r = ds_retrieve_u32("secret_owner", &val);
        if (r == OK) secret_owner = (endpoint_t)val;

        r = ds_retrieve_u32("secret_reader", &val);
        if (r == OK) secret_reader = (endpoint_t)val;

        r = ds_retrieve_u32("secret_len", &val);
        if (r == OK) secret_len = (size_t)val;
    }

    // Announce the driver is ready
    chardriver_announce();

    return OK;
}

static int sef_cb_signal_handler(int signo)
{
    // Handle SIGTERM for graceful termination
    if (signo == SIGTERM) {
        chardriver_terminate();
        return OK;
    }
    return SEF_OTHER_SIGNAL;
}

static void sef_local_startup(void)
{
    // Setup callbacks
    sef_setcb_lu_state_save(sef_cb_lu_state_save);
    sef_setcb_signal_handler(sef_cb_signal_handler);

    // Set name for debugging
    sef_dev_set_name("secret");

    // Initialize SEF (calls sef_cb_init)
    sef_init(sef_cb_init);
}

/* The main function of the Minix driver */
int test453main(void)
{
    // Startup SEF
    sef_local_startup();

    // Start the character driver task
    chardriver_task(&secret_tab, CD_DEV);

    return OK;
}