/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions

   Copyright (C) Andrew Tridgell 1992-1998

   Copyright (C) 2011-2019
   Free Software Foundation, Inc.

   This file is part of the Midnight Commander.

   The Midnight Commander is free software: you can redistribute it
   and/or modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   The Midnight Commander is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#if (defined(HAVE_NETGROUP) && defined (WITH_AUTOMOUNT))
#ifdef WITH_NISPLUS_HOME
#ifdef BROKEN_NISPLUS_INCLUDE_FILES
/*
 * The following lines are needed due to buggy include files
 * in Solaris 2.6 which define GROUP in both /usr/include/sys/acl.h and
 * also in /usr/include/rpcsvc/nis.h. The definitions conflict. JRA.
 * Also GROUP_OBJ is defined as 0x4 in /usr/include/sys/acl.h and as
 * an enum in /usr/include/rpcsvc/nis.h.
 */

#if defined(GROUP)
#undef GROUP
#endif

#if defined(GROUP_OBJ)
#undef GROUP_OBJ
#endif

#endif /* BROKEN_NISPLUS_INCLUDE_FILES */

#include <rpcsvc/nis.h>

#else /* !WITH_NISPLUS_HOME */

#include "rpcsvc/ypclnt.h"

#endif /* WITH_NISPLUS_HOME */
#endif /* HAVE_NETGROUP && WITH_AUTOMOUNT */

#ifdef WITH_SSL
#include <ssl.h>
#undef Realloc                  /* SSLeay defines this and samba has a function of this name */
#endif /* WITH_SSL */

extern int DEBUGLEVEL;

/* a default finfo structure to ensure all fields are sensible */
file_info const def_finfo = { -1, 0, 0, 0, 0, 0, 0, "" };

/* the client file descriptor */
extern int Client;

/* this is used by the chaining code */
const int chain_size = 0;

/*
   case handling on filenames 
 */
const int case_default = CASE_LOWER;

static const char *remote_machine = "";
static const char *local_machine = "";
static const char *remote_arch = "UNKNOWN";
static const char *remote_proto = "UNKNOWN";
pstring myhostname = "";
pstring user_socket_options = "";

static const char sesssetup_user[] = "";
static const char *const samlogon_user = "";

const BOOL sam_logon_in_ssb = False;

pstring global_myname = "";

/****************************************************************************
  find a suitable temporary directory. The result should be copied immediately
  as it may be overwritten by a subsequent call
  ****************************************************************************/
const char *
tmpdir (void)
{
    char *p;
    if ((p = getenv ("MC_TMPDIR")) || (p = getenv ("TMPDIR")))
    {
        return p;
    }
    return "/tmp";
}

/*******************************************************************
copy an IP address from one buffer to another
********************************************************************/
void
putip (void *dest, void *src)
{
    memcpy (dest, src, 4);
}


/****************************************************************************
mangle a name into netbios format

  Note:  <Out> must be (33 + strlen(scope) + 2) bytes long, at minimum.
****************************************************************************/
int
name_mangle (char *In, char *Out, char name_type)
{
    int i;
    int c;
    int len;
    char buf[20];
    char *p = Out;
    extern pstring global_scope;

    /* Safely copy the input string, In, into buf[]. */
    (void) memset (buf, 0, 20);
    if (strcmp (In, "*") == 0)
        buf[0] = '*';
    else
        (void) slprintf (buf, sizeof (buf) - 1, "%-15.15s%c", In, name_type);

    /* Place the length of the first field into the output buffer. */
    p[0] = 32;
    p++;

    /* Now convert the name to the rfc1001/1002 format. */
    for (i = 0; i < 16; i++)
    {
        c = toupper (buf[i]);
        p[i * 2] = ((c >> 4) & 0x000F) + 'A';
        p[(i * 2) + 1] = (c & 0x000F) + 'A';
    }
    p += 32;
    p[0] = '\0';

    /* Add the scope string. */
    for (i = 0, len = 0;; i++, len++)
    {
        switch (global_scope[i])
        {
        case '\0':
            p[0] = len;
            if (len > 0)
                p[len + 1] = 0;
            return (name_len (Out));
        case '.':
            p[0] = len;
            p += (len + 1);
            len = -1;
            break;
        default:
            p[len + 1] = global_scope[i];
            break;
        }
    }

    return (name_len (Out));
}                               /* name_mangle */

/*******************************************************************
  check if a file exists
********************************************************************/
BOOL
file_exist (char *fname, SMB_STRUCT_STAT * sbuf)
{
    SMB_STRUCT_STAT st;
    if (!sbuf)
        sbuf = &st;

    if (sys_stat (fname, sbuf) != 0)
        return (False);

    return (S_ISREG (sbuf->st_mode));
}

/*******************************************************************
check a files mod time
********************************************************************/
time_t
file_modtime (char *fname)
{
    SMB_STRUCT_STAT st;

    if (sys_stat (fname, &st) != 0)
        return (0);

    return (st.st_mtime);
}

/*******************************************************************
return a string representing an attribute for a file
********************************************************************/
char *
attrib_string (uint16 mode)
{
    static char attrstr[7];
    int i = 0;

    attrstr[0] = 0;

    if (mode & aVOLID)
        attrstr[i++] = 'V';
    if (mode & aDIR)
        attrstr[i++] = 'D';
    if (mode & aARCH)
        attrstr[i++] = 'A';
    if (mode & aHIDDEN)
        attrstr[i++] = 'H';
    if (mode & aSYSTEM)
        attrstr[i++] = 'S';
    if (mode & aRONLY)
        attrstr[i++] = 'R';

    attrstr[i] = 0;

    return (attrstr);
}

/*******************************************************************
  show a smb message structure
********************************************************************/
void
show_msg (char *buf)
{
    int i;
    int bcc = 0;

    if (DEBUGLEVEL < 5)
        return;

    DEBUG (5,
           ("size=%d\nsmb_com=0x%x\nsmb_rcls=%d\nsmb_reh=%d\nsmb_err=%d\nsmb_flg=%d\nsmb_flg2=%d\n",
            smb_len (buf), (int) CVAL (buf, smb_com), (int) CVAL (buf, smb_rcls), (int) CVAL (buf,
                                                                                              smb_reh),
            (int) SVAL (buf, smb_err), (int) CVAL (buf, smb_flg), (int) SVAL (buf, smb_flg2)));
    DEBUG (5,
           ("smb_tid=%d\nsmb_pid=%d\nsmb_uid=%d\nsmb_mid=%d\nsmt_wct=%d\n",
            (int) SVAL (buf, smb_tid), (int) SVAL (buf, smb_pid), (int) SVAL (buf, smb_uid),
            (int) SVAL (buf, smb_mid), (int) CVAL (buf, smb_wct)));

    for (i = 0; i < (int) CVAL (buf, smb_wct); i++)
    {
        DEBUG (5, ("smb_vwv[%d]=%d (0x%X)\n", i,
                   SVAL (buf, smb_vwv + 2 * i), SVAL (buf, smb_vwv + 2 * i)));
    }

    bcc = (int) SVAL (buf, smb_vwv + 2 * (CVAL (buf, smb_wct)));

    DEBUG (5, ("smb_bcc=%d\n", bcc));

    if (DEBUGLEVEL < 10)
        return;

    if (DEBUGLEVEL < 50)
    {
        bcc = MIN (bcc, 512);
    }

    dump_data (10, smb_buf (buf), bcc);
}

/*******************************************************************
  return the length of an smb packet
********************************************************************/
int
smb_len (char *buf)
{
    return (PVAL (buf, 3) | (PVAL (buf, 2) << 8) | ((PVAL (buf, 1) & 1) << 16));
}

/*******************************************************************
  set the length of an smb packet
********************************************************************/
void
_smb_setlen (char *buf, int len)
{
    buf[0] = 0;
    buf[1] = (len & 0x10000) >> 16;
    buf[2] = (len & 0xFF00) >> 8;
    buf[3] = len & 0xFF;
}

/*******************************************************************
  set the length and marker of an smb packet
********************************************************************/
void
smb_setlen (char *buf, int len)
{
    _smb_setlen (buf, len);

    CVAL (buf, 4) = 0xFF;
    CVAL (buf, 5) = 'S';
    CVAL (buf, 6) = 'M';
    CVAL (buf, 7) = 'B';
}

/*******************************************************************
  setup the word count and byte count for a smb message
********************************************************************/
int
set_message (char *buf, int num_words, int num_bytes, BOOL zero)
{
    if (zero)
        memset (buf + smb_size, '\0', num_words * 2 + num_bytes);
    CVAL (buf, smb_wct) = num_words;
    SSVAL (buf, smb_vwv + num_words * SIZEOFWORD, num_bytes);
    smb_setlen (buf, smb_size + num_words * 2 + num_bytes - 4);
    return (smb_size + num_words * 2 + num_bytes);
}

/*******************************************************************
return the number of smb words
********************************************************************/
static int
smb_numwords (char *buf)
{
    return (CVAL (buf, smb_wct));
}

/*******************************************************************
return the size of the smb_buf region of a message
********************************************************************/
int
smb_buflen (char *buf)
{
    return (SVAL (buf, smb_vwv0 + smb_numwords (buf) * 2));
}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
static int
smb_buf_ofs (char *buf)
{
    return (smb_size + CVAL (buf, smb_wct) * 2);
}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
char *
smb_buf (char *buf)
{
    return (buf + smb_buf_ofs (buf));
}

/*******************************************************************
return the SMB offset into an SMB buffer
********************************************************************/
int
smb_offset (char *p, char *buf)
{
    return (PTR_DIFF (p, buf + 4) + chain_size);
}

/****************************************************************************
Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
else
if SYSV use O_NDELAY
if BSD use FNDELAY
****************************************************************************/
int
set_blocking (int fd, BOOL set)
{
    int val;
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

    if ((val = fcntl (fd, F_GETFL, 0)) == -1)
        return -1;
    if (set)                    /* Turn blocking on - ie. clear nonblock flag */
        val &= ~FLAG_TO_SET;
    else
        val |= FLAG_TO_SET;
    return fcntl (fd, F_SETFL, val);
#undef FLAG_TO_SET
}


/*******************************************************************
find the difference in milliseconds between two struct timeval
values
********************************************************************/
int
TvalDiff (struct timeval *tvalold, struct timeval *tvalnew)
{
    return ((tvalnew->tv_sec - tvalold->tv_sec) * 1000 +
            ((int) tvalnew->tv_usec - (int) tvalold->tv_usec) / 1000);
}

/****************************************************************************
return the total storage length of a mangled name
****************************************************************************/
int
name_len (char *s1)
{
    /* NOTE: this argument _must_ be unsigned */
    unsigned char *s = (unsigned char *) s1;
    int len;

    /* If the two high bits of the byte are set, return 2. */
    if (0xC0 == (*s & 0xC0))
        return (2);

    /* Add up the length bytes. */
    for (len = 1; (*s); s += (*s) + 1)
    {
        len += *s + 1;
        SMB_ASSERT (len < 80);
    }

    return (len);
}                               /* name_len */


/*******************************************************************
sleep for a specified number of milliseconds
********************************************************************/
void
msleep (int t)
{
    int tdiff = 0;
    struct timeval tval, t1, t2;
    fd_set fds;

    GetTimeOfDay (&t1);
    GetTimeOfDay (&t2);

    while (tdiff < t)
    {
        tval.tv_sec = (t - tdiff) / 1000;
        tval.tv_usec = 1000 * ((t - tdiff) % 1000);

        FD_ZERO (&fds);
        errno = 0;
        sys_select (0, &fds, &tval);

        GetTimeOfDay (&t2);
        tdiff = TvalDiff (&t1, &t2);
    }
}

/****************************************************************************
expand a pointer to be a particular size
****************************************************************************/
void *
Realloc (void *p, size_t size)
{
    void *ret = NULL;

    if (size == 0)
    {
        if (p)
            free (p);
        DEBUG (5, ("Realloc asked for 0 bytes\n"));
        return NULL;
    }

    if (!p)
        ret = (void *) malloc (size);
    else
        ret = (void *) realloc (p, size);

#ifdef MEM_MAN
    {
        extern FILE *dbf;
        smb_mem_write_info (ret, dbf);
    }
#endif

    if (!ret)
        DEBUG (0, ("Memory allocation error: failed to expand to %d bytes\n", (int) size));

    return (ret);
}


/****************************************************************************
get my own name and IP
****************************************************************************/
BOOL
get_myname (char *my_name, struct in_addr * ip)
{
    struct hostent *hp;
    pstring hostname;

    /* cppcheck-suppress uninitvar */
    *hostname = 0;

    /* get my host name */
    if (gethostname (hostname, sizeof (hostname)) == -1)
    {
        DEBUG (0, ("gethostname failed\n"));
        return False;
    }

    /* Ensure null termination. */
    hostname[sizeof (hostname) - 1] = '\0';

    /* get host info */
    if ((hp = Get_Hostbyname (hostname)) == 0)
    {
        DEBUG (0, ("Get_Hostbyname: Unknown host %s\n", hostname));
        return False;
    }

    if (my_name)
    {
        /* split off any parts after an initial . */
        char *p = strchr (hostname, '.');
        if (p)
            *p = 0;

        fstrcpy (my_name, hostname);
    }

    if (ip)
        putip ((char *) ip, (char *) hp->h_addr);

    return (True);
}


/****************************************************************************
true if two IP addresses are equal
****************************************************************************/
BOOL
ip_equal (struct in_addr ip1, struct in_addr ip2)
{
    uint32 a1, a2;
    a1 = ntohl (ip1.s_addr);
    a2 = ntohl (ip2.s_addr);
    return (a1 == a2);
}

/****************************************************************************
interpret an internet address or name into an IP address in 4 byte form
****************************************************************************/
uint32
interpret_addr (const char *str)
{
    struct hostent *hp;
    uint32 res;
    int i;
    BOOL pure_address = True;

    if (strcmp (str, "0.0.0.0") == 0)
        return (0);
    if (strcmp (str, "255.255.255.255") == 0)
        return (0xFFFFFFFF);

    for (i = 0; pure_address && str[i]; i++)
        if (!(isdigit ((int) str[i]) || str[i] == '.'))
            pure_address = False;

    /* if it's in the form of an IP address then get the lib to interpret it */
    if (pure_address)
    {
        res = inet_addr (str);
    }
    else
    {
        /* otherwise assume it's a network name of some sort and use 
           Get_Hostbyname */
        if ((hp = Get_Hostbyname (str)) == 0)
        {
            DEBUG (3, ("Get_Hostbyname: Unknown host. %s\n", str));
            return 0;
        }
        if (hp->h_addr == NULL)
        {
            DEBUG (3, ("Get_Hostbyname: host address is invalid for host %s\n", str));
            return 0;
        }
        putip ((char *) &res, (char *) hp->h_addr);
    }

    if (res == (uint32) - 1)
        return (0);

    return (res);
}

/*******************************************************************
  a convenient addition to interpret_addr()
  ******************************************************************/
struct in_addr *
interpret_addr2 (const char *str)
{
    static struct in_addr ret;
    uint32 a = interpret_addr (str);
    ret.s_addr = a;
    return (&ret);
}

/*******************************************************************
  check if an IP is the 0.0.0.0
  ******************************************************************/
BOOL
zero_ip (struct in_addr ip)
{
    uint32 a;
    putip ((char *) &a, (char *) &ip);
    return (a == 0);
}


/*******************************************************************
 matchname - determine if host name matches IP address 
 ******************************************************************/
BOOL
matchname (char *remotehost, struct in_addr addr)
{
    struct hostent *hp;
    int i;

    if ((hp = Get_Hostbyname (remotehost)) == 0)
    {
        DEBUG (0, ("Get_Hostbyname(%s): lookup failure.\n", remotehost));
        return False;
    }

    /*
     * Make sure that gethostbyname() returns the "correct" host name.
     * Unfortunately, gethostbyname("localhost") sometimes yields
     * "localhost.domain". Since the latter host name comes from the
     * local DNS, we just have to trust it (all bets are off if the local
     * DNS is perverted). We always check the address list, though.
     */

    if (strcasecmp (remotehost, hp->h_name) && strcasecmp (remotehost, "localhost"))
    {
        DEBUG (0, ("host name/name mismatch: %s != %s\n", remotehost, hp->h_name));
        return False;
    }

    /* Look up the host address in the address list we just got. */
    for (i = 0; hp->h_addr_list[i]; i++)
    {
        if (memcmp (hp->h_addr_list[i], (caddr_t) & addr, sizeof (addr)) == 0)
            return True;
    }

    /*
     * The host name does not map to the original host address. Perhaps
     * someone has compromised a name server. More likely someone botched
     * it, but that could be dangerous, too.
     */

    DEBUG (0, ("host name/address mismatch: %s != %s\n", inet_ntoa (addr), hp->h_name));
    return False;
}


#if (defined(HAVE_NETGROUP) && defined(WITH_AUTOMOUNT))
/******************************************************************
 Remove any mount options such as -rsize=2048,wsize=2048 etc.
 Based on a fix from <Thomas.Hepper@icem.de>.
*******************************************************************/

static void
strip_mount_options (pstring * str)
{
    if (**str == '-')
    {
        char *p = *str;
        while (*p && !isspace (*p))
            p++;
        while (*p && isspace (*p))
            p++;
        if (*p)
        {
            pstring tmp_str;

            pstrcpy (tmp_str, p);
            pstrcpy (*str, tmp_str);
        }
    }
}

/*******************************************************************
 Patch from jkf@soton.ac.uk
 Split Luke's automount_server into YP lookup and string splitter
 so can easily implement automount_path(). 
 As we may end up doing both, cache the last YP result. 
*******************************************************************/

#ifdef WITH_NISPLUS_HOME
static char *
automount_lookup (char *user_name)
{
    static fstring last_key = "";
    static pstring last_value = "";

    char *nis_map = (char *) lp_nis_home_map_name ();

    char buffer[NIS_MAXATTRVAL + 1];
    nis_result *result;
    nis_object *object;
    entry_obj *entry;

    DEBUG (5, ("NIS+ Domain: %s\n", (char *) nis_local_directory ()));

    if (strcmp (user_name, last_key))
    {
        slprintf (buffer, sizeof (buffer) - 1, "[%s=%s]%s.%s", "key", user_name, nis_map,
                  (char *) nis_local_directory ());
        DEBUG (5, ("NIS+ querystring: %s\n", buffer));

        if (result = nis_list (buffer, RETURN_RESULT, NULL, NULL))
        {
            if (result->status != NIS_SUCCESS)
            {
                DEBUG (3, ("NIS+ query failed: %s\n", nis_sperrno (result->status)));
                fstrcpy (last_key, "");
                pstrcpy (last_value, "");
            }
            else
            {
                object = result->objects.objects_val;
                if (object->zo_data.zo_type == ENTRY_OBJ)
                {
                    entry = &object->zo_data.objdata_u.en_data;
                    DEBUG (5, ("NIS+ entry type: %s\n", entry->en_type));
                    DEBUG (3,
                           ("NIS+ result: %s\n",
                            entry->en_cols.en_cols_val[1].ec_value.ec_value_val));

                    pstrcpy (last_value, entry->en_cols.en_cols_val[1].ec_value.ec_value_val);
                    string_sub (last_value, "&", user_name);
                    fstrcpy (last_key, user_name);
                }
            }
        }
        nis_freeresult (result);
    }

    strip_mount_options (&last_value);

    DEBUG (4, ("NIS+ Lookup: %s resulted in %s\n", user_name, last_value));
    return last_value;
}
#else /* WITH_NISPLUS_HOME */
static char *
automount_lookup (char *user_name)
{
    static fstring last_key = "";
    static pstring last_value = "";

    int nis_error;              /* returned by yp all functions */
    char *nis_result;           /* yp_match inits this */
    int nis_result_len;         /* and set this */
    char *nis_domain;           /* yp_get_default_domain inits this */
    char *nis_map = (char *) lp_nis_home_map_name ();

    if ((nis_error = yp_get_default_domain (&nis_domain)) != 0)
    {
        DEBUG (3, ("YP Error: %s\n", yperr_string (nis_error)));
        return last_value;
    }

    DEBUG (5, ("NIS Domain: %s\n", nis_domain));

    if (!strcmp (user_name, last_key))
    {
        nis_result = last_value;
        nis_result_len = strlen (last_value);
        nis_error = 0;
    }
    else
    {
        if ((nis_error = yp_match (nis_domain, nis_map,
                                   user_name, strlen (user_name),
                                   &nis_result, &nis_result_len)) != 0)
        {
            DEBUG (3, ("YP Error: \"%s\" while looking up \"%s\" in map \"%s\"\n",
                       yperr_string (nis_error), user_name, nis_map));
        }
        if (!nis_error && nis_result_len >= sizeof (pstring))
        {
            nis_result_len = sizeof (pstring) - 1;
        }
        fstrcpy (last_key, user_name);
        strncpy (last_value, nis_result, nis_result_len);
        last_value[nis_result_len] = '\0';
    }

    strip_mount_options (&last_value);

    DEBUG (4, ("YP Lookup: %s resulted in %s\n", user_name, last_value));
    return last_value;
}
#endif /* WITH_NISPLUS_HOME */
#endif

/*******************************************************************
 Patch from jkf@soton.ac.uk
 This is Luke's original function with the NIS lookup code
 moved out to a separate function.
*******************************************************************/
static char *
automount_server (const char *user_name)
{
    static pstring server_name;
    (void) user_name;

    /* use the local machine name as the default */
    /* this will be the default if WITH_AUTOMOUNT is not used or fails */
    pstrcpy (server_name, local_machine);

#if (defined(HAVE_NETGROUP) && defined (WITH_AUTOMOUNT))

    if (lp_nis_home_map ())
    {
        int home_server_len;
        char *automount_value = automount_lookup (user_name);
        home_server_len = strcspn (automount_value, ":");
        DEBUG (5, ("NIS lookup succeeded.  Home server length: %d\n", home_server_len));
        if (home_server_len > sizeof (pstring))
        {
            home_server_len = sizeof (pstring);
        }
        strncpy (server_name, automount_value, home_server_len);
        server_name[home_server_len] = '\0';
    }
#endif

    DEBUG (4, ("Home server: %s\n", server_name));

    return server_name;
}

/*******************************************************************
 Patch from jkf@soton.ac.uk
 Added this to implement %p (NIS auto-map version of %H)
*******************************************************************/
static char *
automount_path (char *user_name)
{
    static pstring server_path;

    /* use the passwd entry as the default */
    /* this will be the default if WITH_AUTOMOUNT is not used or fails */
    /* pstrcpy() copes with get_home_dir() returning NULL */
    pstrcpy (server_path, get_home_dir (user_name));

#if (defined(HAVE_NETGROUP) && defined (WITH_AUTOMOUNT))

    if (lp_nis_home_map ())
    {
        char *home_path_start;
        char *automount_value = automount_lookup (user_name);
        home_path_start = strchr (automount_value, ':');
        if (home_path_start != NULL)
        {
            DEBUG (5, ("NIS lookup succeeded.  Home path is: %s\n",
                       home_path_start ? (home_path_start + 1) : ""));
            pstrcpy (server_path, home_path_start + 1);
        }
    }
#endif

    DEBUG (4, ("Home server path: %s\n", server_path));

    return server_path;
}


/*******************************************************************
sub strings with useful parameters
Rewritten by Stefaan A Eeckels <Stefaan.Eeckels@ecc.lu> and
Paul Rippin <pr3245@nopc.eurostat.cec.be>
********************************************************************/
void
standard_sub_basic (char *str)
{
    char *s, *p;
    char pidstr[10];
    struct passwd *pass;
    const char *username = sam_logon_in_ssb ? samlogon_user : sesssetup_user;

    for (s = str; s && *s && (p = strchr (s, '%')); s = p)
    {
        switch (*(p + 1))
        {
        case 'G':
            {
                if ((pass = Get_Pwnam (username)) != NULL)
                {
                    string_sub (p, "%G", gidtoname (pass->pw_gid));
                }
                else
                {
                    p += 2;
                }
                break;
            }
        case 'N':
            string_sub (p, "%N", automount_server (username));
            break;
        case 'I':
            string_sub (p, "%I", client_addr (Client));
            break;
        case 'L':
            string_sub (p, "%L", local_machine);
            break;
        case 'M':
            string_sub (p, "%M", client_name (Client));
            break;
        case 'R':
            string_sub (p, "%R", remote_proto);
            break;
        case 'T':
            string_sub (p, "%T", timestring ());
            break;
        case 'U':
            string_sub (p, "%U", username);
            break;
        case 'a':
            string_sub (p, "%a", remote_arch);
            break;
        case 'd':
            {
                slprintf (pidstr, sizeof (pidstr) - 1, "%d", (int) getpid ());
                string_sub (p, "%d", pidstr);
                break;
            }
        case 'h':
            string_sub (p, "%h", myhostname);
            break;
        case 'm':
            string_sub (p, "%m", remote_machine);
            break;
        case 'v':
            string_sub (p, "%v", VERSION);
            break;
        case '$':              /* Expand environment variables */
            {
                /* Contributed by Branko Cibej <branko.cibej@hermes.si> */
                fstring envname;
                char *envval;
                char *q, *r;
                int copylen;

                if (*(p + 2) != '(')
                {
                    p += 2;
                    break;
                }
                if ((q = strchr (p, ')')) == NULL)
                {
                    DEBUG (0, ("standard_sub_basic: Unterminated environment \
					variable [%s]\n", p));
                    p += 2;
                    break;
                }

                r = p + 3;
                copylen = MIN ((size_t) (q - r), (size_t) (sizeof (envname) - 1));
                strncpy (envname, r, copylen);
                envname[copylen] = '\0';

                if ((envval = getenv (envname)) == NULL)
                {
                    DEBUG (0, ("standard_sub_basic: Environment variable [%s] not set\n", envname));
                    p += 2;
                    break;
                }

                copylen = MIN ((size_t) (q + 1 - p), (size_t) (sizeof (envname) - 1));
                strncpy (envname, p, copylen);
                envname[copylen] = '\0';
                string_sub (p, envname, envval);
                break;
            }
        case '\0':
            p++;
            break;              /* don't run off end if last character is % */
        default:
            p += 2;
            break;
        }
    }
    return;
}


/****************************************************************************
do some standard substitutions in a string
****************************************************************************/
void
standard_sub (connection_struct * conn, char *str)
{
    char *p, *s;
    const char *home;

    for (s = str; (p = strchr (s, '%')); s = p)
    {
        switch (*(p + 1))
        {
        case 'H':
            if ((home = get_home_dir (conn->user)))
            {
                string_sub (p, "%H", home);
            }
            else
            {
                p += 2;
            }
            break;

        case 'P':
            string_sub (p, "%P", conn->connectpath);
            break;

        case 'S':
            string_sub (p, "%S", lp_servicename (SNUM (conn)));
            break;

        case 'g':
            string_sub (p, "%g", gidtoname (conn->gid));
            break;
        case 'u':
            string_sub (p, "%u", conn->user);
            break;

            /* Patch from jkf@soton.ac.uk Left the %N (NIS
             * server name) in standard_sub_basic as it is
             * a feature for logon servers, hence uses the
             * username.  The %p (NIS server path) code is
             * here as it is used instead of the default
             * "path =" string in [homes] and so needs the
             * service name, not the username.  */
        case 'p':
            string_sub (p, "%p", automount_path (lp_servicename (SNUM (conn))));
            break;
        case '\0':
            p++;
            break;              /* don't run off the end of the string 
                                 */

        default:
            p += 2;
            break;
        }
    }

    standard_sub_basic (str);
}



/*******************************************************************
are two IPs on the same subnet?
********************************************************************/
BOOL
same_net (struct in_addr ip1, struct in_addr ip2, struct in_addr mask)
{
    uint32 net1, net2, nmask;

    nmask = ntohl (mask.s_addr);
    net1 = ntohl (ip1.s_addr);
    net2 = ntohl (ip2.s_addr);

    return ((net1 & nmask) == (net2 & nmask));
}


/****************************************************************************
a wrapper for gethostbyname() that tries with all lower and all upper case 
if the initial name fails
****************************************************************************/
struct hostent *
Get_Hostbyname (const char *name)
{
    char *name2 = strdup (name);
    struct hostent *ret;

    if (!name2)
    {
        DEBUG (0, ("Memory allocation error in Get_Hostbyname! panic\n"));
        exit (0);
    }


    /* 
     * This next test is redundent and causes some systems (with
     * broken isalnum() calls) problems.
     * JRA.
     */

    ret = sys_gethostbyname (name2);
    if (ret != NULL)
    {
        free (name2);
        return (ret);
    }

    /* try with all lowercase */
    strlower (name2);
    ret = sys_gethostbyname (name2);
    if (ret != NULL)
    {
        free (name2);
        return (ret);
    }

    /* try with all uppercase */
    strupper (name2);
    ret = sys_gethostbyname (name2);
    if (ret != NULL)
    {
        free (name2);
        return (ret);
    }

    /* nothing works :-( */
    free (name2);
    return (NULL);
}

/*******************************************************************
turn a gid into a group name
********************************************************************/

char *
gidtoname (gid_t gid)
{
    static char name[40];
    struct group *grp = getgrgid (gid);
    if (grp)
        return (grp->gr_name);
    slprintf (name, sizeof (name) - 1, "%d", (int) gid);
    return (name);
}

/*******************************************************************
something really nasty happened - panic!
********************************************************************/
void
smb_panic (const char *why)
{
    const char *cmd = lp_panic_action ();
    if (cmd && *cmd)
    {
        if (system (cmd))
        {
            DEBUG (0, ("PANIC: cannot run panic handler command \"%s\"\n", cmd));
        }
    }
    DEBUG (0, ("PANIC: %s\n", why));
    dbgflush ();
    abort ();
}

void
print_asc (int level, unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        DEBUG (level, ("%c", isprint (buf[i]) ? buf[i] : '.'));
}

void
dump_data (int level, char *buf1, int len)
{
    unsigned char *buf = (unsigned char *) buf1;
    int i = 0;
    if (len <= 0)
        return;

    DEBUG (level, ("[%03X] ", i));
    for (i = 0; i < len;)
    {
        DEBUG (level, ("%02X ", (int) buf[i]));
        i++;
        if (i % 8 == 0)
            DEBUG (level, (" "));
        if (i % 16 == 0)
        {
            print_asc (level, &buf[i - 16], 8);
            DEBUG (level, (" "));
            print_asc (level, &buf[i - 8], 8);
            DEBUG (level, ("\n"));
            if (i < len)
                DEBUG (level, ("[%03X] ", i));
        }
    }
    if (i % 16)
    {
        int n;

        n = 16 - (i % 16);
        DEBUG (level, (" "));
        if (n > 8)
            DEBUG (level, (" "));
        while (n--)
            DEBUG (level, ("   "));

        n = MIN (8, i % 16);
        print_asc (level, &buf[i - (i % 16)], n);
        DEBUG (level, (" "));
        n = (i % 16) - n;
        if (n > 0)
            print_asc (level, &buf[i - n], n);
        DEBUG (level, ("\n"));
    }
}
