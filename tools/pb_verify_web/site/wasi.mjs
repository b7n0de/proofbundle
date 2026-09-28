// The WASI preview 1 calls that pb_verify_rs makes, and nothing more.
//
// pb_verify_rs is compiled unchanged for wasm32-wasip1, so the browser runs the same main(), the same
// argument parsing and the same exit codes as the native binary. This module gives it what a
// command line gives it: arguments, standard output and error, read-only files and an exit code.
//
// Files come from a backend with two functions:
//   stat(path) -> {type: "file" | "dir" | "other", size} or null when the path does not exist
//   read(path) -> Uint8Array
// The page backs them with files the user picked (nothing leaves the tab); the Node runner backs
// them with the local file system. Every file is opened read-only: an open that asks to create,
// truncate or write is refused.

const ERRNO = { SUCCESS: 0, ACCES: 2, BADF: 8, INVAL: 28, ISDIR: 31, NOENT: 44 };
const FILETYPE = { unknown: 0, char: 2, dir: 3, file: 4 };
const OFLAGS_CREAT = 1, OFLAGS_DIRECTORY = 2, OFLAGS_EXCL = 4, OFLAGS_TRUNC = 8;
const RIGHTS_FD_WRITE = 1n << 6n;
const ALL_RIGHTS = 0xffffffffffffffffn;
const PREOPEN_FD = 3;

export class WasiExit extends Error {
  constructor(code) {
    super(`exit ${code}`);
    this.code = code;
  }
}

/** Join a path relative to the preopened "/" into an absolute one. */
function resolve(rel) {
  const parts = [];
  for (const seg of ("/" + rel).split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  return "/" + parts.join("/");
}

/**
 * Run a compiled WASI command to its end.
 * @param {WebAssembly.Module} module the compiled pb_verify_rs.wasm
 * @param {{args: string[], fs: {stat: Function, read: Function}, randomFill: Function}} options
 *   args includes argv[0]; randomFill(Uint8Array) fills bytes (crypto.getRandomValues)
 * @returns {Promise<{exitCode: number, stdout: Uint8Array, stderr: Uint8Array, trap?: string}>}
 */
export async function runWasi(module, { args, fs, randomFill }) {
  const enc = new TextEncoder();
  const argBytes = args.map((a) => enc.encode(a + "\0"));
  const out = { 1: [], 2: [] };
  const open = new Map(); // fd -> {data: Uint8Array, pos: number}
  let nextFd = PREOPEN_FD + 1;
  let memory;
  const view = () => new DataView(memory.buffer);
  const bytes = () => new Uint8Array(memory.buffer);
  const text = (ptr, len) => new TextDecoder().decode(bytes().subarray(ptr, ptr + len));

  const wasi = {
    args_sizes_get(argcPtr, bufSizePtr) {
      view().setUint32(argcPtr, argBytes.length, true);
      view().setUint32(bufSizePtr, argBytes.reduce((n, b) => n + b.length, 0), true);
      return ERRNO.SUCCESS;
    },
    args_get(argvPtr, bufPtr) {
      let p = bufPtr;
      argBytes.forEach((b, i) => {
        view().setUint32(argvPtr + 4 * i, p, true);
        bytes().set(b, p);
        p += b.length;
      });
      return ERRNO.SUCCESS;
    },
    environ_sizes_get(countPtr, sizePtr) {
      view().setUint32(countPtr, 0, true);
      view().setUint32(sizePtr, 0, true);
      return ERRNO.SUCCESS;
    },
    environ_get() {
      return ERRNO.SUCCESS;
    },
    random_get(ptr, len) {
      for (let off = 0; off < len; off += 65536) {
        randomFill(bytes().subarray(ptr + off, ptr + Math.min(len, off + 65536)));
      }
      return ERRNO.SUCCESS;
    },
    fd_write(fd, iovs, iovsLen, nwrittenPtr) {
      if (!(fd in out)) return ERRNO.BADF;
      let n = 0;
      for (let i = 0; i < iovsLen; i++) {
        const buf = view().getUint32(iovs + 8 * i, true);
        const len = view().getUint32(iovs + 8 * i + 4, true);
        out[fd].push(bytes().slice(buf, buf + len));
        n += len;
      }
      view().setUint32(nwrittenPtr, n, true);
      return ERRNO.SUCCESS;
    },
    fd_read(fd, iovs, iovsLen, nreadPtr) {
      if (fd === 0) {
        view().setUint32(nreadPtr, 0, true);
        return ERRNO.SUCCESS;
      }
      const f = open.get(fd);
      if (!f) return ERRNO.BADF;
      let n = 0;
      for (let i = 0; i < iovsLen && f.pos < f.data.length; i++) {
        const buf = view().getUint32(iovs + 8 * i, true);
        const len = view().getUint32(iovs + 8 * i + 4, true);
        const chunk = f.data.subarray(f.pos, f.pos + len);
        bytes().set(chunk, buf);
        f.pos += chunk.length;
        n += chunk.length;
      }
      view().setUint32(nreadPtr, n, true);
      return ERRNO.SUCCESS;
    },
    fd_close(fd) {
      if (open.delete(fd) || fd <= PREOPEN_FD) return ERRNO.SUCCESS;
      return ERRNO.BADF;
    },
    fd_fdstat_get(fd, ptr) {
      let type;
      if (fd <= 2) type = FILETYPE.char;
      else if (fd === PREOPEN_FD) type = FILETYPE.dir;
      else if (open.has(fd)) type = FILETYPE.file;
      else return ERRNO.BADF;
      const v = view();
      v.setUint8(ptr, type);
      v.setUint16(ptr + 2, 0, true);
      v.setBigUint64(ptr + 8, ALL_RIGHTS, true);
      v.setBigUint64(ptr + 16, ALL_RIGHTS, true);
      return ERRNO.SUCCESS;
    },
    fd_prestat_get(fd, ptr) {
      if (fd !== PREOPEN_FD) return ERRNO.BADF;
      view().setUint8(ptr, 0);
      view().setUint32(ptr + 4, 1, true);
      return ERRNO.SUCCESS;
    },
    fd_prestat_dir_name(fd, ptr, len) {
      if (fd !== PREOPEN_FD) return ERRNO.BADF;
      if (len < 1) return ERRNO.INVAL;
      bytes()[ptr] = 0x2f; // "/"
      return ERRNO.SUCCESS;
    },
    path_filestat_get(dirfd, _flags, pathPtr, pathLen, bufPtr) {
      if (dirfd !== PREOPEN_FD) return ERRNO.BADF;
      const st = fs.stat(resolve(text(pathPtr, pathLen)));
      if (!st) return ERRNO.NOENT;
      const v = view();
      for (let off = 0; off < 64; off += 8) v.setBigUint64(bufPtr + off, 0n, true);
      v.setUint8(bufPtr + 16, FILETYPE[st.type] ?? FILETYPE.unknown);
      v.setBigUint64(bufPtr + 24, 1n, true);
      v.setBigUint64(bufPtr + 32, BigInt(st.size), true);
      return ERRNO.SUCCESS;
    },
    path_open(dirfd, _dirflags, pathPtr, pathLen, oflags, rightsBase, _rightsInh, _fdflags, fdPtr) {
      if (dirfd !== PREOPEN_FD) return ERRNO.BADF;
      if (oflags & (OFLAGS_CREAT | OFLAGS_EXCL | OFLAGS_TRUNC)) return ERRNO.ACCES;
      if (BigInt(rightsBase) & RIGHTS_FD_WRITE) return ERRNO.ACCES;
      const path = resolve(text(pathPtr, pathLen));
      const st = fs.stat(path);
      if (!st) return ERRNO.NOENT;
      if (st.type === "dir" || oflags & OFLAGS_DIRECTORY) return ERRNO.ISDIR;
      const fd = nextFd++;
      open.set(fd, { data: fs.read(path), pos: 0 });
      view().setUint32(fdPtr, fd, true);
      return ERRNO.SUCCESS;
    },
    proc_exit(code) {
      throw new WasiExit(code);
    },
  };

  const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: wasi });
  memory = instance.exports.memory;
  const join = (chunks) => {
    const all = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let p = 0;
    for (const c of chunks) {
      all.set(c, p);
      p += c.length;
    }
    return all;
  };
  const result = { exitCode: 0 };
  try {
    instance.exports._start();
  } catch (e) {
    if (e instanceof WasiExit) result.exitCode = e.code;
    else if (e instanceof WebAssembly.RuntimeError) {
      // A Rust panic aborts, which traps. The native binary exits 101 on a panic; a trap is kept
      // apart and reported as such, never mapped onto a verdict.
      result.exitCode = null;
      result.trap = String(e.message);
    } else throw e;
  }
  result.stdout = join(out[1]);
  result.stderr = join(out[2]);
  return result;
}
