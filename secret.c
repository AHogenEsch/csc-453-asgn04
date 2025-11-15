#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <minix/const.h> // R_BIT and W_BIT
#include <sys/ioc_secret.h> // SSGRANT definition (relies on this header for SSGRANT)
#include <sys/ucred.h> // struct ucred
#include <minix/syslib.h> // sys_getnucred (or getnucred based on pln.h)
#include <sys/types.h>
#include <minix/sef.h> // For SEF functions
#include <signal.h> // For SIGTERM

#include "secret.h" // For SECRET_SIZE

// SSGRANT definition removed to prevent redefinition conflict with pln.h

#ifndef SSREVOKE
// Define SSREVOKE manually if not provided by sys/ioc_secret.h
#define SSREVOKE _IO('S', 2) /* Revoke ownership of the secret from a reader */
#endif

/* State of the device */
static char secret_data[SECRET_SIZE];
static size_t secret_len = 0;
// Replaced NONE with 0, as NONE is often undefined without minix/endpoint.h
static endpoint_t secret_owner = 0;
static endpoint_t secret_reader = 0;


/* Function Prototypes for the character driver table */
// Removed 'static' from nop_prepare to resolve conflict with pln.h prototype
struct device *nop_prepare(int device);
static void nop_cleanup(int minor);
static int secret_open(devminor_t minor, int flags);
static int secret_close(devminor_t minor);
static int secret_ioctl(devminor_t minor, unsigned long request, endpoint_t user_endpt, cp_grant_id_t grant);
static ssize_t secret_transfer(devminor_t minor, int operation, endpoint_t user_endpt,
    cp_grant_id_t grant, size_t pos, size_t num_bytes, int flags);

/* SEF function prototypes */
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
// Corrected signature for state save
static void sef_cb_lu_state_save(void);
static int sef_cb_signal_handler(int signo);

// Dummy prototype for get_endpoint_by_uid (to satisfy ioctl compilation).
// This function is expected to be provided by the environment's system libraries.
int get_endpoint_by_uid(uid_t uid, endpoint_t *endpt);


/* Character driver entry points */
static struct chardriver secret_tab =
{
    .cdr_prepare = nop_prepare,
    .cdr_cleanup = nop_cleanup, // Corrected from cdr_end
    .cdr_open = secret_open,
    .cdr_close = secret_close,
    .cdr_ioctl = secret_ioctl,
    .cdr_transfer = secret_transfer,
    .cdr_cancel = NULL,
    .cdr_select = NULL,
    .cdr_alarm = NULL,
    .cdr_other = NULL
};


/* No-op function for prepare */
struct device *nop_prepare(int device)
{
    static struct device dev;
    UNUSED(device);
    return &dev;
}

static void nop_cleanup(int minor)
{
    UNUSED(minor);
}

/* Helper function to get the current user's UID */
static uid_t get_caller_uid(endpoint_t user_endpt)
{
    struct ucred ucred;
    // Fix: Using the 2-argument prototype from pln.h (endpoint, struct ucred *),
    // which resolves the "too many arguments" and "incompatible pointer type" errors.
    if (getnucred(user_endpt, &ucred) != OK) {
        return (uid_t)-1;
    }
    // Return the Real UID (ruid) as the owner identity
    return ucred.ruid;
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

    // Check for R/W access attempt, which is forbidden
    if ((flags & (R_BIT | W_BIT)) == (R_BIT | W_BIT)) {
        return EACCES;
    }

    // Case 1: Device is not owned (secret_owner is 0)
    if (secret_owner == 0) {
        // Any open (R or W) on an empty device makes the process owner
        if (flags & (W_BIT | R_BIT)) {
            secret_owner = user_endpt;
            return OK;
        }
        return EACCES;
    }

    // Case 2: Device is owned (secret_owner is not 0)
    if (secret_owner != 0) {
        // Deny write access if it's already owned
        if (flags & W_BIT) {
            return EACCES;
        }

        // Allow read access only if the user is the owner or the granted reader
        if (flags & R_BIT) {
            if (user_endpt == secret_owner || user_endpt == secret_reader) {
                return OK;
            } else {
                // Deny read access to all others
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
    if (user_endpt == secret_owner) {
        secret_owner = 0;
        secret_reader = 0;
        secret_len = 0;
    }
    // Non-owner readers close their file descriptor, but the grant remains until revoked.

    return OK;
}

/* Read/Write transfer routine */
static ssize_t secret_transfer(devminor_t minor, int operation, endpoint_t user_endpt,
    cp_grant_id_t grant, size_t pos, size_t num_bytes, int flags)
{
    ssize_t bytes_transferred = 0;

    UNUSED(minor);
    UNUSED(flags);

    if (secret_owner == 0) {
        return EACCES;
    }

    // Fix: Assuming DEV_READ and DEV_WRITE are defined in minix/drivers.h or chardriver.h
    if (operation == DEV_READ) {
        if (user_endpt != secret_owner && user_endpt != secret_reader) {
            return EACCES;
        }

        if (pos >= secret_len) {
            return 0; // EOF
        }
        if (pos + num_bytes > secret_len) {
            num_bytes = secret_len - pos;
        }

        if (sys_safecopyto(user_endpt, grant, 0,
            (vir_bytes)(secret_data + pos), num_bytes) != OK) {
            return EIO;
        }

        bytes_transferred = num_bytes;

    } else if (operation == DEV_WRITE) {
        if (user_endpt != secret_owner) {
            return EACCES;
        }

        if (pos + num_bytes > SECRET_SIZE) {
            if (pos >= SECRET_SIZE) {
                return ENOSPC;
            }
            num_bytes = SECRET_SIZE - pos;
        }

        if (sys_safecopyfrom(user_endpt, grant, 0,
            (vir_bytes)(secret_data + pos), num_bytes) != OK) {
            return EIO;
        }

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
            // Owner grants read permission to a target UID.
            size_t size = sizeof(target_uid);

            // Copy the target UID from the user process via grant
            if (sys_safecopyfrom(user_endpt, grant, 0, (vir_bytes)&target_uid, size) != OK) {
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
            // Owner revokes read permission
            secret_reader = 0;
            return OK;
        }

        default:
            return ENOTTY;
    }
}


/* SEF Callbacks */

// Fix: Corrected signature from (int state, int flags) to (void)
static void sef_cb_lu_state_save(void)
{
    // Fix: ds_publish_u32 requires 3 arguments (name, value, flags), added 0 for flags.
    ds_publish_u32("secret_owner", secret_owner, 0);
    ds_publish_u32("secret_reader", secret_reader, 0);
    ds_publish_u32("secret_len", (u32_t)secret_len, 0);
}

// Fixed signature for sef_cb_init
static int sef_cb_init(int type, sef_init_info_t *info)
{
    UNUSED(info);

    if (type == SEF_INIT_FRESH) {
        secret_owner = 0;
        secret_reader = 0;
        secret_len = 0;
    } else if (type == SEF_INIT_LU) {
        u32_t val;
        int r;

        r = ds_retrieve_u32("secret_owner", &val);
        if (r == OK) secret_owner = (endpoint_t)val;

        r = ds_retrieve_u32("secret_reader", &val);
        if (r == OK) secret_reader = (endpoint_t)val;

        r = ds_retrieve_u32("secret_len", &val);
        if (r == OK) secret_len = (size_t)val;
    }

    // Announce we are up and running
    chardriver_announce();

    return OK;
}

// Signal handler (for graceful termination)
static int sef_cb_signal_handler(int signo)
{
    if (signo != SIGTERM) return SEF_OTHER_SIGNAL;

    // Graceful termination
    chardriver_terminate();
    return OK;
}

// Local startup routine
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

/* The main function of the Minix driver (renamed from main to test453main) */
int test453main(void)
{
    // Startup SEF
    sef_local_startup();

    // Start the character driver task
    // Fix: Using CD_DEV instead of the undeclared CD_TASK
    chardriver_task(&secret_tab, CD_DEV);

    return OK;
}