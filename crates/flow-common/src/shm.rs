//! Shared memory SPSC ring buffer.
//!
//! Provides a lock-free ring buffer backed by shared memory (`/dev/shm/` on Linux,
//! or equivalent on other platforms via `memmap2`), suitable for zero-copy IPC
//! between independent processes.

use memmap2::MmapMut;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Marker trait for types that are safe to store in shared memory.
///
/// # Safety
///
/// Implementors must be `Copy`, `Clone`, and `#[repr(C)]` with no pointers
/// or references. All bit patterns of the type must be valid.
pub unsafe trait Pod: Copy + Clone {}

// SAFETY: All bit patterns of these primitive types are valid.
unsafe impl Pod for u8 {}
unsafe impl Pod for u16 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for u64 {}
unsafe impl Pod for i8 {}
unsafe impl Pod for i16 {}
unsafe impl Pod for i32 {}
unsafe impl Pod for i64 {}

/// Memory layout of the ring buffer in shared memory.
///
/// ```text
/// [header: 32 bytes] [data slots: capacity * sizeof(T)]
///   - read_index:  u64 (8 bytes)  — consumer position
///   - write_index: u64 (8 bytes)  — producer position
///   - capacity:    u64 (8 bytes)  — number of slots
///   - element_size: u64 (8 bytes) — sizeof(T)
/// ```
#[repr(C)]
struct Header {
    /// Index of the next slot to read (consumer).
    read_index: AtomicU64,
    /// Index of the next slot to write (producer).
    write_index: AtomicU64,
    /// Number of usable slots (capacity).
    capacity: u64,
    /// Size of each element in bytes.
    element_size: u64,
}

const HEADER_SIZE: usize = 32;

/// A single-producer, single-consumer ring buffer backed by shared memory.
///
/// # Safety
///
/// This type is `Send` and `Sync`. The ring buffer uses atomic operations
/// for coordination between producer and consumer processes.
///
/// The buffer is identified by a name. On Linux, the shared memory file is
/// stored under `/dev/shm/flowfang-{name}`.
pub struct ShmRingBuf<T: Pod> {
    mmap: MmapMut,
    _phantom: PhantomData<T>,
}

impl<T: Pod> ShmRingBuf<T> {
    /// Create a new shared memory ring buffer.
    ///
    /// `capacity` is the number of elements (not bytes). The underlying shared
    /// memory region includes space for the header plus `capacity` slots.
    pub fn create(name: &str, capacity: usize) -> Result<Self, io::Error> {
        let path = shm_path(name);
        let element_size = std::mem::size_of::<T>();
        let total_size = HEADER_SIZE + capacity * element_size;

        // Remove any existing file
        let _ = fs::remove_file(&path);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;

        file.set_len(total_size as u64)?;

        // SAFETY: The mmap is backed by a file we just created with the correct size.
        let mmap = unsafe { MmapMut::map_mut(&file)? };
        drop(file); // fd no longer needed after mmap

        // Initialize the header
        // SAFETY: The mmap is at least HEADER_SIZE bytes.
        let header = unsafe { &*(mmap.as_ptr() as *const Header) };
        header.read_index.store(0, Ordering::SeqCst);
        header.write_index.store(0, Ordering::SeqCst);
        // SAFETY: capacity and element_size are immutable after init, so writing
        // through a shared reference via raw pointer is acceptable for initialization.
        let header_mut = mmap.as_ptr() as *mut Header;
        // SAFETY: We own the mmap and the header is within bounds.
        unsafe {
            (*header_mut).capacity = capacity as u64;
            (*header_mut).element_size = element_size as u64;
        }

        Ok(Self {
            mmap,
            _phantom: PhantomData,
        })
    }

    /// Open an existing shared memory ring buffer.
    pub fn open(name: &str) -> Result<Self, io::Error> {
        let path = shm_path(name);
        let file = OpenOptions::new().read(true).write(true).open(&path)?;

        // SAFETY: The mmap is backed by the existing file. We trust the file
        // was created by ShmRingBuf::create and has the correct layout.
        let mmap = unsafe { MmapMut::map_mut(&file)? };

        Ok(Self {
            mmap,
            _phantom: PhantomData,
        })
    }

    /// Try to push an item into the buffer.
    ///
    /// Returns `Ok(true)` if the item was pushed, `Ok(false)` if the buffer is full.
    pub fn try_push(&self, item: &T) -> Result<bool, io::Error> {
        let header = self.header();
        let write = header.write_index.load(Ordering::Acquire);
        let read = header.read_index.load(Ordering::Acquire);
        let capacity = header.capacity;

        if write.wrapping_sub(read) >= capacity {
            // Buffer is full
            return Ok(false);
        }

        let slot_index = (write % capacity) as usize;
        // SAFETY: The data region starts at offset HEADER_SIZE in the mmap.
        // We write to slot_index which is within [0, capacity).
        let data_ptr = unsafe { self.mmap.as_ptr().add(HEADER_SIZE) as *mut T };
        // SAFETY: data_ptr + slot_index is within the mmap bounds.
        unsafe {
            data_ptr.add(slot_index).write(*item);
        }

        header.write_index.store(write.wrapping_add(1), Ordering::Release);

        Ok(true)
    }

    /// Try to pop an item from the buffer.
    ///
    /// Returns `Ok(Some(item))` if an item was popped, `Ok(None)` if the buffer is empty.
    pub fn try_pop(&self) -> Result<Option<T>, io::Error> {
        let header = self.header();
        let read = header.read_index.load(Ordering::Acquire);
        let write = header.write_index.load(Ordering::Acquire);

        if read == write {
            // Buffer is empty
            return Ok(None);
        }

        let capacity = header.capacity;
        let slot_index = (read % capacity) as usize;
        // SAFETY: The data region starts at offset HEADER_SIZE. slot_index is within [0, capacity).
        let data_ptr = unsafe { self.mmap.as_ptr().add(HEADER_SIZE) as *const T };
        // SAFETY: data_ptr + slot_index is within mmap bounds, and the slot was
        // previously written by the producer.
        let item = unsafe { data_ptr.add(slot_index).read() };

        header.read_index.store(read.wrapping_add(1), Ordering::Release);

        Ok(Some(item))
    }

    /// Return a reference to the header in the mmap.
    fn header(&self) -> &Header {
        // SAFETY: The mmap is at least HEADER_SIZE bytes, and the Header layout
        // matches the bytes written during create().
        unsafe { &*(self.mmap.as_ptr() as *const Header) }
    }
}

/// Get the shared memory file path for a given name.
fn shm_path(name: &str) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/dev/shm").join(format!("flowfang-{}", name))
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::temp_dir().join(format!("flowfang-{}", name))
    }
}

// SAFETY: ShmRingBuf uses atomic operations for all coordination. The mmap
// is the only shared state, and concurrent access is safe with the
// SPSC discipline (one producer, one consumer).
unsafe impl<T: Pod> Send for ShmRingBuf<T> {}
unsafe impl<T: Pod> Sync for ShmRingBuf<T> {}