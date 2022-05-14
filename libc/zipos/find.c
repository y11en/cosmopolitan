/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2020 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "ape/relocations.h"
#include "libc/assert.h"
#include "libc/bits/safemacros.internal.h"
#include "libc/intrin/kprintf.h"
#include "libc/nexgen32e/crc32.h"
#include "libc/runtime/runtime.h"
#include "libc/str/str.h"
#include "libc/zip.h"
#include "libc/zipos/zipos.internal.h"

ssize_t __zipos_lookup(struct Zipos *zipos, const char *path, size_t size) {
  uint32_t hash;
  const char *zname;
  size_t i, n, c, step, znamesize;
  if (zipos->paths.n) {
    step = 0;
    hash = max(1, crc32c(0, path, size));
    do {
      i = (hash + step * ((step + 1) >> 1)) & (zipos->paths.n - 1);
      if (hash == zipos->paths.p[i].hash) {
        zname = ZIP_CFILE_NAME(zipos->map + zipos->paths.p[i].c);
        znamesize = ZIP_CFILE_NAMESIZE(zipos->map + zipos->paths.p[i].c);
        if (znamesize == size && !memcmp(path, zname, znamesize)) {
          return zipos->paths.p[i].c;
        }
      }
      ++step;
    } while (zipos->paths.p[i].hash);
  }
  return -1;
}

// searches for `path` and `path/` in hash table
// returns map-relative offset of central directory entry
ssize_t __zipos_find(struct Zipos *zipos, const struct ZiposUri *name) {
  char *s;
  ssize_t rc;
  const char *zname;
  size_t i, n, c, znamesize;
  if ((rc = __zipos_lookup(zipos, name->path, name->len)) == -1) {
    if ((s = malloc(name->len + 2))) {
      stpcpy(mempcpy(s, name->path, name->len), "/");
      rc = __zipos_lookup(zipos, s, name->len + 1);
      free(s);
    }
  }
  return rc;
}
