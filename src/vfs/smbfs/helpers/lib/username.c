/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Username handling

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
extern int DEBUGLEVEL;

/* internal functions */
static struct passwd *uname_string_combinations (char *s, struct passwd *(*fn) (const char *),
                                                 int N);
static struct passwd *uname_string_combinations2 (char *s, int offset,
                                                  struct passwd *(*fn) (const char *), int N);

/****************************************************************************
get a users home directory.
****************************************************************************/
const char *
get_home_dir (char *user)
{
    struct passwd *pass;

    pass = Get_Pwnam (user);

    if (!pass)
        return (NULL);
    return (pass->pw_dir);
}

/****************************************************************************
Get_Pwnam wrapper
****************************************************************************/
static struct passwd *
_Get_Pwnam (const char *s)
{
    struct passwd *ret;

    ret = getpwnam (s);
    if (ret)
    {
#ifdef HAVE_GETPWANAM
        struct passwd_adjunct *pwret;
        pwret = getpwanam (s);
        if (pwret)
        {
            free (ret->pw_passwd);
            ret->pw_passwd = pwret->pwa_passwd;
        }
#endif

    }

    return (ret);
}


/****************************************************************************
a wrapper for getpwnam() that tries with all lower and all upper case 
if the initial name fails. Also tried with first letter capitalised
****************************************************************************/
struct passwd *
Get_Pwnam (const char *a_user)
{
    fstring user;
    int last_char;
    int usernamelevel = lp_usernamelevel ();

    struct passwd *ret;

    if (!a_user || !(*a_user))
        return (NULL);

    StrnCpy (user, a_user, sizeof (user) - 1);

    ret = _Get_Pwnam (user);
    if (ret)
        return (ret);

    strlower (user);
    ret = _Get_Pwnam (user);
    if (ret)
        return (ret);

    strupper (user);
    ret = _Get_Pwnam (user);
    if (ret)
        return (ret);

    /* try with first letter capitalised */
    if (strlen (user) > 1)
        strlower (user + 1);
    ret = _Get_Pwnam (user);
    if (ret)
        return (ret);

    /* try with last letter capitalised */
    strlower (user);
    last_char = strlen (user) - 1;
    user[last_char] = toupper (user[last_char]);
    ret = _Get_Pwnam (user);
    if (ret)
        return (ret);

    /* try all combinations up to usernamelevel */
    strlower (user);
    ret = uname_string_combinations (user, _Get_Pwnam, usernamelevel);
    if (ret)
        return (ret);

    return (NULL);
}

/* The functions below have been taken from password.c and slightly modified */
/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static struct passwd *
uname_string_combinations2 (char *s, int offset, struct passwd *(*fn) (const char *), int N)
{
    int len = strlen (s);
    int i;
    struct passwd *ret;

#ifdef PASSWORD_LENGTH
    len = MIN (len, PASSWORD_LENGTH);
#endif

    if (N <= 0 || offset >= len)
        return (fn (s));


    for (i = offset; i < (len - (N - 1)); i++)

    {
        char c = s[i];
        if (!islower (c))
            continue;
        s[i] = toupper (c);
        ret = uname_string_combinations2 (s, i + 1, fn, N - 1);
        if (ret)
            return (ret);
        s[i] = c;
    }
    return (NULL);
}

/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with up to N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static struct passwd *
uname_string_combinations (char *s, struct passwd *(*fn) (const char *), int N)
{
    int n;
    struct passwd *ret;

    for (n = 1; n <= N; n++)
    {
        ret = uname_string_combinations2 (s, 0, fn, n);
        if (ret)
            return (ret);
    }
    return (NULL);
}
