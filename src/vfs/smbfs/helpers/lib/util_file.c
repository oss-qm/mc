/*
   Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup

   Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.

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

/****************************************************************************
read a line from a file with possible \ continuation chars. 
Blanks at the start or end of a line are stripped.
The string will be allocated if s2 is NULL
****************************************************************************/
char *
fgets_slash (char *s2, int maxlen, FILE * f)
{
    char *s = s2;
    int len = 0;
    int c;
    BOOL start_of_line = True;

    if (feof (f))
        return (NULL);

    if (!s2)
    {
        maxlen = MIN (maxlen, 8);
        s = (char *) Realloc (s, maxlen);
    }

    if (!s || maxlen < 2)
        return (NULL);

    *s = 0;

    while (len < maxlen - 1)
    {
        c = getc (f);
        switch (c)
        {
        case '\r':
            break;
        case '\n':
            while (len > 0 && s[len - 1] == ' ')
            {
                s[--len] = 0;
            }
            if (len > 0 && s[len - 1] == '\\')
            {
                s[--len] = 0;
                start_of_line = True;
                break;
            }
            return (s);
        case EOF:
            if (len <= 0 && !s2)
                free (s);
            return (len > 0 ? s : NULL);
        case ' ':
            if (start_of_line)
                break;
        default:
            start_of_line = False;
            s[len++] = c;
            s[len] = 0;
        }
        if (!s2 && len > maxlen - 3)
        {
            maxlen *= 2;
            s = (char *) Realloc (s, maxlen);
            if (!s)
                return (NULL);
        }
    }
    return (s);
}
