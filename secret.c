#include <minix/drivers.h>
#include <minix/driver.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/ioc_chr_drv.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <lib.h>

/* Max size of the secret buffer (8KB) */
#define MAX_SECRET_SIZE 8192 
/* IOCTL command to grant read access to a specific user */
#define SSGRANT _IOW('S', 1, int)
/* IOCTL command to revoke read access from all granted users */
#define SSREVOKE _IO('S', 2)

/* Secret device state */
static char secret_data[MAX_SECRET_SIZE];
static size_t secret_size = 0;
static endpoint_t secret_owner = NONE;
static endpoint_t secret_grantee = NONE;
static int is_secret_full = 0;

/* Function prototypes for the character driver callbacks */
static int secret_open(dev_t minor, int access, endpoint_t user_endpt);
static int secret_close(dev_t minor);
static int secret_ioctl(dev_t minor, unsigned long request, endpoint_t endpt, cp_grant_id_t grant, int flags);
static struct device *nop_prepare(dev_t dev);
static int secret_transfer(dev_t minor, int operation, off_t position, cp_grant_id_t grant, size_t chunk, int flags);

/* SEF Callbacks */
static int sef_cb_init(int type, sef_init_info_t *info);
static int sef_cb_lu_state_save(int state, int flags);
static void sef_cb_signal_handler(int signo);

/* The character driver table */
static struct chardriver secret_tab =
{
    .cdr_open       = secret_open,
    .cdr_close      = secret_close,
    .cdr_ioctl      = secret_ioctl,
    .cdr_prepare    = nop_prepare,
    .cdr_transfer   = secret_transfer,
    .cdr_cleanup    = NULL
};

/* --- Driver Helper Functions (Must use system prototypes) --- */

/* The nop_prepare function must return struct device * and take dev_t (or int) */
static struct device *nop_prepare(dev_t dev)
{
    /* Use the system-defined UNUSED macro within the function body */
    UNUSED(dev);
    /* Character drivers typically return NULL for this function */
    return NULL;
}

/* --- Driver Callbacks --- */

/**
 * secret_open: Handles /dev/Secret open requests.
 * @minor: The minor device number (always 0 for this device).
 * @access: Requested access mode (R_BIT for read, W_BIT for write).
 * @user_endpt: The endpoint of the calling process.
 */
static int secret_open(dev_t minor, int access, endpoint_t user_endpt)
{
    UNUSED(minor);

    /* 1. Check for read/write (O_RDWR) access, which is forbidden. */
    if ((access & (R_BIT | W_BIT)) == (R_BIT | W_BIT)) {
        return EACCES;
    }

    /* 2. Opening for Writing (W_BIT) */
    if (access & W_BIT) {
        /* Only one writer is allowed: if already full/owned, deny access. */
        if (is_secret_full) {
            return EBUSY;
        }

        /* If empty (secret_owner == NONE), the current user becomes the owner. */
        secret_owner = user_endpt;
        /* The device is considered "full" (owned) once opened for writing. */
        is_secret_full = 1;

        /* Get the UID of the owner process (optional, but good practice if needed later) */
        struct ucred ucr;
        int r = getnucred(secret_owner, &ucr);
        if (r == OK) {
            dt_printf("secret: Open for WRITE by endpoint %d, UID %d, now owner.\n", secret_owner, ucr.uid);
        } else {
            dt_printf("secret: Open for WRITE by endpoint %d, UID unknown (getnucred failed), now owner.\n", secret_owner);
        }
        
        return OK;
    }

    /* 3. Opening for Reading (R_BIT) */
    if (access & R_BIT) {
        /* A. If not owned by anyone, any reader is allowed, and they become the owner. */
        if (!is_secret_full) {
            secret_owner = user_endpt;
            is_secret_full = 1;
            dt_printf("secret: Open for READ by endpoint %d, now owner (empty device).\n", user_endpt);
            return OK;
        }

        /* B. If owned, only the owner or the granted user may read. */
        if (user_endpt == secret_owner || user_endpt == secret_grantee) {
            dt_printf("secret: Open for READ by authorized endpoint %d.\n", user_endpt);
            return OK;
        }

        /* C. Deny access to all others. */
        return EACCES;
    }

    /* Should not be reached, but safety return for no access bits set. */
    return EACCES;
}

/**
 * secret_close: Handles /dev/Secret close requests.
 * @minor: The minor device number.
 */
static int secret_close(dev_t minor)
{
    UNUSED(minor);
    dt_printf("secret: Close called by endpoint %d.\n", secret_owner);

    /* Close always succeeds, but we must clear state if the owner is closing. */
    secret_size = 0;
    secret_owner = NONE;
    secret_grantee = NONE;
    is_secret_full = 0;
    
    return OK;
}

/**
 * secret_transfer: Handles read/write requests (replacing cdr_read/cdr_write).
 * @minor: The minor device number.
 * @operation: The operation (DEV_GATHER_S for read, DEV_SCATTER_S for write).
 * @position: The offset in the device to start the transfer.
 * @grant: The grant ID for safe copy operations.
 * @chunk: The size of the data to transfer.
 * @flags: Transfer flags.
 */
static int secret_transfer(dev_t minor, int operation, off_t position, cp_grant_id_t grant, size_t chunk, int flags)
{
    endpoint_t user_endpt = chardriver_get_caller_endpt();
    int r;

    UNUSED(minor);
    UNUSED(flags);

    if (user_endpt == NONE) {
        dt_printf("secret: transfer failed, no caller endpoint.\n");
        return EIO;
    }

    /* 1. Check permissions and state based on operation */
    if (operation == DEV_SCATTER_S) { /* Write operation */
        /* Only the current owner can write, and only if position is 0 (overwrite/initial write) */
        if (user_endpt != secret_owner) {
            return EACCES;
        }
        if (position != 0) {
            return ENXIO; /* Cannot seek/append to secret */
        }
        if (chunk > MAX_SECRET_SIZE) {
            return ENOSPC; /* No space left on device */
        }
        
        /* Copy data from user to device buffer */
        r = sys_safecopyfrom(user_endpt, grant, 0, (vir_bytes)secret_data, chunk);
        if (r != OK) {
            dt_printf("secret: sys_safecopyfrom failed: %d\n", r);
            return r;
        }

        secret_size = chunk;
        dt_printf("secret: Wrote %zu bytes by owner %d.\n", secret_size, user_endpt);
        return chunk;
    } 
    else if (operation == DEV_GATHER_S) { /* Read operation */
        /* Only owner or grantee can read */
        if (user_endpt != secret_owner && user_endpt != secret_grantee) {
            return EACCES;
        }
        if (position != 0) {
            return ENXIO; /* Cannot seek/read from an offset */
        }
        if (chunk > secret_size) {
            chunk = secret_size; /* Only read up to the size of the secret */
        }
        
        /* Copy data from device buffer to user */
        r = sys_safecopyto(user_endpt, grant, 0, (vir_bytes)secret_data, chunk);
        if (r != OK) {
            dt_printf("secret: sys_safecopyto failed: %d\n", r);
            return r;
        }

        dt_printf("secret: Read %zu bytes by endpoint %d.\n", chunk, user_endpt);
        return chunk;
    } 
    
    return EINVAL; /* Invalid operation */
}

/**
 * secret_ioctl: Handles IOCTL requests (SSGRANT and SSREVOKE).
 * @minor: Minor device number.
 * @request: The IOCTL request code.
 * @endpt: The endpoint of the calling process.
 * @grant: The grant ID (unused for this assignment's IOCTLs).
 * @flags: IOCTL flags.
 */
static int secret_ioctl(dev_t minor, unsigned long request, endpoint_t endpt, cp_grant_id_t grant, int flags)
{
    UNUSED(minor);
    UNUSED(grant);
    UNUSED(flags);

    /* Only the owner of the secret can perform IOCTLs */
    if (endpt != secret_owner) {
        return EACCES;
    }

    switch (request) {
        case SSGRANT: {
            int target_uid;
            
            /* Get the target UID from the grant */
            int r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes)&target_uid, sizeof(int));
            if (r != OK) {
                dt_printf("secret: SSGRANT sys_safecopyfrom failed: %d\n", r);
                return r;
            }

            /* Find the endpoint associated with the target UID */
            endpoint_t target_endpt;
            r = get_endpoint_by_uid(target_uid, &target_endpt);
            if (r != OK) {
                dt_printf("secret: SSGRANT failed: could not find endpoint for UID %d\n", target_uid);
                return EINVAL;
            }

            secret_grantee = target_endpt;
            dt_printf("secret: SSGRANT: granted read access to endpoint %d (UID %d).\n", target_endpt, target_uid);
            return OK;
        }

        case SSREVOKE:
            secret_grantee = NONE;
            dt_printf("secret: SSREVOKE: revoked read access from all.\n");
            return OK;

        default:
            return EINVAL; /* Invalid request */
    }
}


/* --- SEF Callbacks --- */

/**
 * sef_cb_lu_state_save: Saves the driver's state (for live update).
 * @state: The current state value (unused here).
 * @flags: The flags value (unused here).
 */
static int sef_cb_lu_state_save(int state, int flags)
{
    /* Use the system-defined UNUSED macro within the function body */
    UNUSED(state);
    UNUSED(flags);

    /* In a real implementation, you would save the state variables here. */
    dt_printf("secret: Live update state save not implemented.\n");
    return OK;
}

/**
 * sef_cb_init: Initializes the driver.
 * @type: The initialization type.
 * @info: Pointer to initialization information.
 */
static int sef_cb_init(int type, sef_init_info_t *info)
{
    /* Use the system-defined UNUSED macro within the function body */
    UNUSED(info);

    switch(type) {
        case SEF_INIT_FRESH:
            dt_printf("secret: Starting up, fresh state.\n");
            break;

        case SEF_INIT_LU:
            dt_printf("secret: Starting up, restored state from live update.\n");
            break;

        case SEF_INIT_RESTART:
            dt_printf("secret: Starting up, restarted.\n");
            break;
    }

    /* Initialize device state */
    secret_owner = NONE;
    secret_grantee = NONE;
    secret_size = 0;
    is_secret_full = 0;

    /* Ready to start service */
    return OK;
}

/**
 * sef_local_startup: Performs local SEF (Self-Executable Format) setup.
 */
static void sef_local_startup(void)
{
    /* Set up callbacks and initialization */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);
    sef_setcb_lu_state_save(sef_cb_lu_state_save);
    sef_setcb_signal_handler(sef_cb_signal_handler);

    /* Set up driver name */
    sef_dev_set_name("secret");

    /* Let SEF perform startup */
    sef_startup();
}

/**
 * sef_cb_signal_handler: Catches termination signals.
 */
static void sef_cb_signal_handler(int signo)
{
    /* Only check for termination signal, ignore anything else */
    if (signo != SIGTERM) return;
    dt_printf("secret: Caught SIGTERM signal, exiting.\n");
    sef_exit(0);
}

/**
 * The main entry point for the driver.
 * The test harness renames main() to test453main().
 */
int test453main(void)
{
    sef_local_startup();
    
    /* The call must include the second argument: driver_type (CD_TASK) */
    chardriver_task(&secret_tab, CD_TASK);

    return 0;
}