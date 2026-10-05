//! Local-file race protection, NOT authentication against arbitrary same-UID code.
use std::path::Path;

pub(crate) struct PinnedProofFile {
    #[cfg(unix)]
    inner: local::Pinned,
}
impl PinnedProofFile {
    pub(crate) fn open(root: &Path) -> Result<Self, &'static str> {
        #[cfg(unix)]
        {
            Ok(Self {
                inner: local::Pinned::open(root)?,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            Err("unsupported_platform")
        }
    }
    pub(crate) fn read(&mut self) -> Result<Vec<u8>, &'static str> {
        #[cfg(unix)]
        {
            self.inner.read(|| {})
        }
        #[cfg(not(unix))]
        {
            Err("unsupported_platform")
        }
    }
}

#[cfg(unix)]
mod local {
    use std::{
        ffi::CString,
        fs::{File, Metadata},
        io::{Read, Seek, SeekFrom},
        os::unix::{
            fs::MetadataExt,
            io::{AsRawFd, FromRawFd},
        },
        path::{Component, Path},
    };
    fn open(parent: &File, name: &str, directory: bool) -> Result<File, &'static str> {
        let name = CString::new(name).map_err(|_| "untrusted_extension_path")?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if directory { libc::O_DIRECTORY } else { 0 };
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err("untrusted_extension_path");
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn same(a: &Metadata, b: &Metadata) -> bool {
        (
            a.dev(),
            a.ino(),
            a.uid(),
            a.mode(),
            a.nlink(),
            a.len(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.dev(),
            b.ino(),
            b.uid(),
            b.mode(),
            b.nlink(),
            b.len(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        )
    }
    fn directory(meta: &Metadata, private: bool) -> Result<(), &'static str> {
        let uid = unsafe { libc::geteuid() };
        if !meta.is_dir()
            || (meta.uid() != uid && meta.uid() != 0)
            || meta.mode() & 0o022 != 0
            || (private && (meta.uid() != uid || meta.mode() & 0o077 != 0))
        {
            return Err("untrusted_extension_path");
        }
        Ok(())
    }
    pub(super) struct Pinned {
        chain: Vec<File>,
        names: Vec<String>,
        file: File,
        baseline: Metadata,
    }
    impl Pinned {
        pub(super) fn open(root: &Path) -> Result<Self, &'static str> {
            if !root.is_absolute() {
                return Err("untrusted_extension_path");
            }
            let mut chain = vec![File::open("/").map_err(|_| "extension_unavailable")?];
            let mut names = Vec::new();
            for part in root.components() {
                let name = match part {
                    Component::RootDir => continue,
                    Component::Normal(n) => n.to_str().ok_or("untrusted_extension_path")?,
                    _ => return Err("untrusted_extension_path"),
                };
                let dir = open(chain.last().unwrap(), name, true)?;
                directory(&dir.metadata().map_err(|_| "extension_unavailable")?, false)?;
                chain.push(dir);
                names.push(name.to_owned());
            }
            let dir = chain.last().unwrap();
            directory(&dir.metadata().map_err(|_| "extension_unavailable")?, true)?;
            let file = open(dir, "proof-identity.json", false)?;
            let baseline = file.metadata().map_err(|_| "extension_unavailable")?;
            if !baseline.is_file()
                || baseline.uid() != unsafe { libc::geteuid() }
                || baseline.mode() & 0o077 != 0
                || baseline.nlink() != 1
                || baseline.len() > 4096
            {
                return Err("untrusted_extension_path");
            }
            Ok(Self {
                chain,
                names,
                file,
                baseline,
            })
        }
        pub(super) fn read(&mut self, between: impl FnOnce()) -> Result<Vec<u8>, &'static str> {
            if !same(
                &self.baseline,
                &self.file.metadata().map_err(|_| "extension_unavailable")?,
            ) {
                return Err("extension_identity_changed");
            }
            between();
            self.file
                .seek(SeekFrom::Start(0))
                .map_err(|_| "extension_unavailable")?;
            let mut bytes = Vec::new();
            (&mut self.file)
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| "extension_unavailable")?;
            if bytes.len() > 4096
                || !same(
                    &self.baseline,
                    &self.file.metadata().map_err(|_| "extension_unavailable")?,
                )
            {
                return Err("extension_identity_changed");
            }
            // Revalidate entries against held fds, never reopen to read. This
            // remains pinned across both preflight and admission reads.
            for (i, name) in self.names.iter().enumerate() {
                let current = open(&self.chain[i], name, true)?;
                let a = self.chain[i + 1]
                    .metadata()
                    .map_err(|_| "extension_unavailable")?;
                let b = current.metadata().map_err(|_| "extension_unavailable")?;
                directory(&a, i + 1 == self.chain.len() - 1)?;
                if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                    return Err("extension_identity_changed");
                }
            }
            let current = open(self.chain.last().unwrap(), "proof-identity.json", false)?;
            if !same(
                &self.baseline,
                &current.metadata().map_err(|_| "extension_unavailable")?,
            ) {
                return Err("extension_identity_changed");
            }
            Ok(bytes)
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    fn root() -> std::path::PathBuf {
        let p = std::env::current_dir()
            .unwrap()
            .join("scratch")
            .join(format!(
                "discovery-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        p
    }
    fn read(p: &Path) -> Result<Vec<u8>, &'static str> {
        PinnedProofFile::open(p)?.read()
    }
    #[test]
    fn checked_fd_rejects_replacement_mid_read_and_between_reads() {
        let p = root();
        let f = p.join("proof-identity.json");
        fs::write(&f, b"original").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        let mut pin = PinnedProofFile::open(&p).unwrap();
        assert_eq!(pin.read().unwrap(), b"original");
        fs::rename(&f, p.join("old")).unwrap();
        fs::write(&f, b"original").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(pin.read().unwrap_err(), "extension_identity_changed");
        let mut pin = local::Pinned::open(&p).unwrap();
        let result = pin.read(|| {
            fs::rename(&f, p.join("old2")).unwrap();
            fs::write(&f, b"substitute").unwrap();
            fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        });
        assert_eq!(result.unwrap_err(), "extension_identity_changed");
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn discovery_rejects_symlinks_hardlinks_modes_and_oversize() {
        let p = root();
        let f = p.join("proof-identity.json");
        fs::write(p.join("source"), b"{}").unwrap();
        symlink(p.join("source"), &f).unwrap();
        assert!(read(&p).is_err());
        fs::remove_file(&f).unwrap();
        fs::hard_link(p.join("source"), &f).unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read(&p).is_err());
        fs::remove_file(&f).unwrap();
        fs::write(&f, b"{}").unwrap();
        assert!(read(&p).is_err());
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read(&p).unwrap(), b"{}");
        fs::write(&f, vec![b'x'; 4097]).unwrap();
        assert!(read(&p).is_err());
        let ancestor_link = p.with_extension("link");
        symlink(&p, &ancestor_link).unwrap();
        assert!(read(&ancestor_link).is_err());
        fs::remove_file(ancestor_link).unwrap();
        fs::remove_dir_all(p).unwrap();
    }
}
