#![no_std]

pub mod block;
pub mod inode;

extern crate alloc;

use alloc::{format, vec};
use alloc::vec::Vec;
use core::mem::MaybeUninit;


#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    InvalidSuperblock,
    DeviceError,
    InodeNotFound,
    NotADirectory,
    FileExists,
    DirectoryExists,
    NoSpace,
    Other(&'static str),
}


pub trait InOutDevice {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Error>;
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), Error>;
    fn size(&self) -> u64;
    fn close(&self) -> Result<(), Error>;
}


#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IllFs<D: InOutDevice> {
    pub device: D,
    pub superblock: block::Superblock,
    pub block_bitmap: block::BitMap,
    pub inode_bitmap: block::BitMap,
    pub inode_table: Vec<inode::Inode>,
}



impl<D: InOutDevice> IllFs<D> {
    pub fn mount(mut device: D) -> Result<Self, Error> {
        // Read and validate superblock
        let mut superblock_buf = [0u8; size_of::<block::Superblock>()];

        device.read(0, &mut superblock_buf)?;

        let superblock: block::Superblock = unsafe {
            core::ptr::read_unaligned(superblock_buf.as_ptr() as *const block::Superblock)
        };
        if superblock.magic != block::ILLFS_MAGIC || superblock.version != block::ILLFS_VERSION {
            return Err(Error::InvalidSuperblock);
        }

        // Load block bitmap
        let disk_bytes =
            superblock.blocks_bitmap_blocks as usize * block::BLOCK_SIZE;

        let mut disk_buf = vec![0u8; disk_bytes];
        device.read(
            superblock.blocks_bitmap_start * block::BLOCK_SIZE as u64,
            &mut disk_buf,
        )?;

        let block_count = superblock.block_count as usize;

        let bitmap_bytes = block_count.div_ceil(8);

        disk_buf.truncate(bitmap_bytes);

        let block_bitmap = block::BitMap {
            bits: disk_buf,
        };

        // Load inode bitmap
        let mut inode_bitmap_buf = vec![0u8; (superblock.inode_bitmap_blocks as usize) * block::BLOCK_SIZE];
        device.read(superblock.inode_bitmap_start * block::BLOCK_SIZE as u64, &mut inode_bitmap_buf)?;
        let inode_bitmap = block::BitMap { bits: inode_bitmap_buf };

        // Load inode table
        let inode_table_size =
            superblock.inodes_table_blocks as usize * block::BLOCK_SIZE / size_of::<inode::Inode>();


        let mut inode_table: Vec<MaybeUninit<inode::Inode>> = Vec::with_capacity(inode_table_size);
        unsafe {
            inode_table.set_len(inode_table_size);
        }

        let bytes = inode_table_size * size_of::<inode::Inode>();
        let offset = superblock.inodes_table_start  * block::BLOCK_SIZE as u64;

        let buf = unsafe {
            core::slice::from_raw_parts_mut(
                inode_table.as_mut_ptr() as *mut u8,
                bytes,
            )
        };

        device.read(offset, buf)?;


        Ok(IllFs {
            device,
            superblock,
            block_bitmap,
            inode_bitmap,
            inode_table: inode_table
                .iter()
                .map(|inode| unsafe { inode.assume_init() })
                .collect(),
        })
    }

    pub fn make_filesystem(mut device: D) -> Result<Self, Error> {
        // zero out the device

        let size = device.size();
        for offset in (0..size).step_by(block::BLOCK_SIZE) {
            let zero_block = [0u8; block::BLOCK_SIZE];
            device.write(offset, &zero_block)?;
        }
        let block_count = size / block::BLOCK_SIZE as u64;
        let inode_count = block_count / 4;
        let block_bitmap_bsize = block_count.div_ceil(8);
        let inode_bitmap_bsize = inode_count.div_ceil(8);
        let inode_table_bsize = inode_count * size_of::<inode::Inode>() as u64;
        let block_bitmap_start = 1;
        let block_bitmap_blocks = block_bitmap_bsize.div_ceil(block::BLOCK_SIZE as u64);
        let inode_bitmap_start = block_bitmap_start + block_bitmap_blocks;
        let inode_bitmap_blocks = inode_bitmap_bsize.div_ceil(block::BLOCK_SIZE as u64);
        let inodes_table_start = inode_bitmap_start + inode_bitmap_blocks;
        let inodes_table_blocks = inode_table_bsize.div_ceil(block::BLOCK_SIZE as u64);
        let superblock = block::Superblock {
            magic: block::ILLFS_MAGIC,
            version: block::ILLFS_VERSION,
            block_size: block::BLOCK_SIZE as u64,
            block_count,
            inode_count,
            blocks_start: inodes_table_start + inodes_table_blocks,
            blocks_bitmap_start: block_bitmap_start,
            blocks_bitmap_blocks: block_bitmap_blocks,
            inode_bitmap_start,
            inode_bitmap_blocks,
            inodes_table_start,
            inodes_table_blocks,
        };
        let superblock_buf: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &superblock as *const block::Superblock as *const u8,
                size_of::<block::Superblock>(),
            )
        };
        device.write(0, superblock_buf)?;
        let mut block_bitmap = block::BitMap::new(block_count as usize);
        let inode_bitmap = block::BitMap::new(inode_count as usize);
        let block_bitmap_buf: &[u8] = &block_bitmap.bits;
        device.write(
            block_bitmap_start * block::BLOCK_SIZE as u64,
            block_bitmap_buf,
        )?;
        let inode_bitmap_buf: &[u8] = &inode_bitmap.bits;
        device.write(
            inode_bitmap_start * block::BLOCK_SIZE as u64,
            inode_bitmap_buf,
        )?;
        let mut inode_table: Vec<inode::Inode> = vec![inode::Inode::default(); inode_count as usize];
        inode_table[1].used = 1;
        inode_table[1].inode_type = inode::InodeType::Directory;
        inode_table[1].size = size_of::<u64>() as u64;
        inode_table[1].block_count = 1;
        inode_table[1].blocks[0] = inodes_table_start + inodes_table_blocks;
        block_bitmap.set(inode_table[1].blocks[0] as usize, true);
        let root_dir_buf = 0u64.to_le_bytes();
        device.write(
            inode_table[1].blocks[0] * block::BLOCK_SIZE as u64,
            &root_dir_buf,
        )?;
        device.write(
            inodes_table_start * block::BLOCK_SIZE as u64,
            unsafe {
                core::slice::from_raw_parts(
                    inode_table.as_ptr() as *const u8,
                    inode_table.len() * size_of::<inode::Inode>(),
                )
            },
        )?;
        Ok(IllFs {
            device,
            superblock,
            block_bitmap,
            inode_bitmap,
            inode_table,
        })

    }

    pub fn sync(&mut self) -> Result<(), Error> {
        // write back superblock, bitmaps, and inode table
        let superblock_buf: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &self.superblock as *const block::Superblock as *const u8,
                size_of::<block::Superblock>(),
            )
        };
        self.device.write(0, superblock_buf)?;
        let bitmap_bytes = self.block_bitmap.bits.len();
        let bitmap_blocks = self.superblock.blocks_bitmap_blocks as usize;
        let total_bytes = bitmap_blocks * block::BLOCK_SIZE;

        let mut buf = vec![0u8; total_bytes];
        buf[..bitmap_bytes].copy_from_slice(&self.block_bitmap.bits);

        for i in 0..bitmap_blocks {
            let offset =
                self.superblock.blocks_bitmap_start * block::BLOCK_SIZE as u64
                    + (i as u64 * block::BLOCK_SIZE as u64);

            let start = i * block::BLOCK_SIZE;
            let end = start + block::BLOCK_SIZE;

            self.device.write(offset, &buf[start..end])?;
        }

        let bitmap_bytes = self.inode_bitmap.bits.len();
        let bitmap_blocks = self.superblock.inode_bitmap_blocks as usize;
        let total_bytes = bitmap_blocks * block::BLOCK_SIZE;

        let mut buf = vec![0u8; total_bytes];
        buf[..bitmap_bytes].copy_from_slice(&self.inode_bitmap.bits);

        for i in 0..bitmap_blocks {
            let offset =
                self.superblock.inode_bitmap_start * block::BLOCK_SIZE as u64
                    + (i as u64 * block::BLOCK_SIZE as u64);

            let start = i * block::BLOCK_SIZE;
            let end = start + block::BLOCK_SIZE;

            self.device.write(offset, &buf[start..end])?;
        }

        let inode_table_bytes = self.inode_table.len() * size_of::<inode::Inode>();
        let inode_table_blocks = self.superblock.inodes_table_blocks as usize;
        let total_bytes = inode_table_blocks * block::BLOCK_SIZE;

        let mut buf = vec![0u8; total_bytes];

        unsafe {
            let src = core::slice::from_raw_parts(
                self.inode_table.as_ptr() as *const u8,
                inode_table_bytes,
            );
            buf[..inode_table_bytes].copy_from_slice(src);
        }

        for i in 0..inode_table_blocks {
            let offset =
                self.superblock.inodes_table_start * block::BLOCK_SIZE as u64
                    + (i as u64 * block::BLOCK_SIZE as u64);

            let start = i * block::BLOCK_SIZE;
            let end = start + block::BLOCK_SIZE;

            self.device.write(offset, &buf[start..end])?;
        }

        Ok(())
    }

    pub fn block_read(&mut self, block_index: u64, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() != block::BLOCK_SIZE {
            return Err(Error::Other("Buffer size mismatch"));
        }
        let offset = block_index * block::BLOCK_SIZE as u64;
        self.device.read(offset, buf)
    }

    pub fn block_write(&mut self, block_index: u64, buf: &[u8]) -> Result<(), Error> {
        if buf.len() != block::BLOCK_SIZE {
            return Err(Error::Other("Buffer size mismatch"));
        }
        let offset = block_index * block::BLOCK_SIZE as u64;
        self.device.write(offset, buf)
    }

    pub fn directory_open(&mut self, inode_index: usize) -> Result<inode::Directory, Error> {
        if inode_index >= self.inode_table.len() {
            return Err(Error::InodeNotFound);
        }
        let inode = self.inode_table[inode_index];
        if inode.used == 0 || inode.inode_type != inode::InodeType::Directory {
            return Err(Error::NotADirectory);
        }
        let mut dir_buf = vec![0u8; block::BLOCK_SIZE];
        self.block_read(inode.blocks[0], &mut dir_buf)?;

        dir_buf.truncate(inode.size as usize);

        let inode_count = u64::from_le_bytes(dir_buf[..8].try_into().unwrap());

        let mut entries: Vec<MaybeUninit<inode::DirectoryEntry>> = Vec::with_capacity(inode_count as usize);
        let offset = size_of::<u64>();

        unsafe {
            entries.set_len(inode_count as usize);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(
                dir_buf[offset..].as_ptr(),
                entries.as_mut_ptr() as *mut u8,
                (inode_count as usize) * size_of::<inode::DirectoryEntry>(),
            );
        }

        let dir = inode::Directory {
            inode_count,
            entries: entries
                .iter()
                .map(|entry| unsafe { entry.assume_init() })
                .collect(),
        };

        Ok(dir)
    }

    pub fn set_directory(&mut self, inode_index: usize, dir: &inode::Directory) -> Result<(), Error> {
        if inode_index >= self.inode_table.len() {
            return Err(Error::InodeNotFound);
        }
        if self.inode_table[inode_index].used == 0 || self.inode_table[inode_index].inode_type != inode::InodeType::Directory {
            return Err(Error::NotADirectory);
        }

        let dir_size = size_of::<u64>() + dir.entries.len() * size_of::<inode::DirectoryEntry>();
        let mut dir_buf = vec![0u8; block::BLOCK_SIZE];

        let inode_count_bytes = dir.inode_count.to_le_bytes();
        dir_buf[..size_of::<u64>()].copy_from_slice(&inode_count_bytes);

        unsafe {
            core::ptr::copy_nonoverlapping(
                dir.entries.as_ptr() as *const u8,
                dir_buf[size_of::<u64>()..].as_mut_ptr(),
                dir.entries.len() * size_of::<inode::DirectoryEntry>(),
            );
        }

        self.block_write(self.inode_table[inode_index].blocks[0], &dir_buf)?;

        self.inode_table[inode_index].size = dir_size as u64;

        Ok(())
    }

    pub fn resolve_path(&mut self, path: &str) -> Result<usize, Error> {
        let mut current_inode_index = 1; // Start from root directory
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        for component in components {
            let dir = self.directory_open(current_inode_index)?;
            let mut found = false;

            for entry in dir.entries.iter() {
                if entry.name_as_str() == component {
                    current_inode_index = entry.inode as usize;
                    found = true;
                    break;
                }
            }

            if !found {
                return Err(Error::InodeNotFound); // Component not found
            }
        }

        Ok(current_inode_index)
    }

    pub fn allocate_block(&mut self) -> Result<u64, Error> {
        for i in self.superblock.blocks_start..self.superblock.block_count {
            let i = i as usize;
            if !self.block_bitmap.get(i) {
                self.block_bitmap.set(i, true);
                return Ok(i as u64);
            }
        }
        Err(Error::NoSpace)
    }

    pub fn allocate_inode(&mut self) -> Result<usize, Error> {
        for i in 2..self.superblock.inode_count as usize {
            if !self.inode_bitmap.get(i) {
                self.inode_bitmap.set(i, true);
                return Ok(i);
            }
        }
        Err(Error::NoSpace)
    }

    pub fn create_file(&mut self, path: &str) -> Result<usize, Error> {
        if !path.starts_with('/') {
            return Err(Error::Other("Path must start with /"));
        }

        let parent_path = if let Some(pos) = path.rfind('/') {
            if pos == 0 {
                "/"
            } else {
                &path[..pos]
            }
        } else {
            return Err(Error::Other("Invalid path"));
        };

        let file_name = if let Some(pos) = path.rfind('/') {
            &path[pos + 1..]
        } else {
            path
        };

        if file_name.is_empty() {
            return Err(Error::Other("File name cannot be empty"));
        }
        if file_name.len() >= inode::MAX_STRING_SIZE {
            return Err(Error::Other("File name too long"));
        }

        let parent_inode_index = self.resolve_path(parent_path)?;

        if self.inode_table[parent_inode_index].inode_type != inode::InodeType::Directory {
            return Err(Error::NotADirectory);
        }

        let mut parent_dir = self.directory_open(parent_inode_index)?;

        for entry in parent_dir.entries.iter() {
            if entry.name_as_str() == file_name {
                return Err(Error::FileExists);
            }
        }


        let new_inode_index = self.allocate_inode()?;

        self.inode_table[new_inode_index].used = 1;
        self.inode_table[new_inode_index].inode_type = inode::InodeType::File;
        self.inode_table[new_inode_index].size = 0;
        self.inode_table[new_inode_index].block_count = 0;

        let mut entry = inode::DirectoryEntry {
            inode: new_inode_index as u64,
            name: [0; inode::MAX_STRING_SIZE],
        };
        let name_bytes = file_name.as_bytes();
        entry.name[..name_bytes.len()].copy_from_slice(name_bytes);

        self.inode_table[parent_inode_index].size += size_of::<inode::DirectoryEntry>() as u64;

        parent_dir.entries.push(entry);
        parent_dir.inode_count += 1;

        self.set_directory(parent_inode_index, &parent_dir)?;

        Ok(new_inode_index)
    }

    pub fn create_directory(&mut self, path: &str) -> Result<usize, Error> {
        if !path.starts_with('/') {
            return Err(Error::Other("Path must start with /"));
        }

        let parent_path = if let Some(pos) = path.rfind('/') {
            if pos == 0 {
                "/"
            } else {
                &path[..pos]
            }
        } else {
            return Err(Error::Other("Invalid path"));
        };

        let dir_name = if let Some(pos) = path.rfind('/') {
            &path[pos + 1..]
        } else {
            path
        };

        if dir_name.is_empty() {
            return Err(Error::Other("Directory name cannot be empty"));
        }
        if dir_name.len() >= inode::MAX_STRING_SIZE {
            return Err(Error::Other("Directory name too long"));
        }

        let parent_inode_index = self.resolve_path(parent_path)?;

        if self.inode_table[parent_inode_index].inode_type != inode::InodeType::Directory {
            return Err(Error::NotADirectory);
        }

        let mut parent_dir = self.directory_open(parent_inode_index)?;

        for entry in parent_dir.entries.iter() {
            if entry.name_as_str() == dir_name {
                return Err(Error::DirectoryExists);
            }
        }

        let new_block = self.allocate_block()?;

        let new_inode_index = self.allocate_inode()?;

        self.inode_table[new_inode_index].used = 1;
        self.inode_table[new_inode_index].inode_type = inode::InodeType::Directory;
        self.inode_table[new_inode_index].size = size_of::<u64>() as u64;
        self.inode_table[new_inode_index].block_count = 1;
        self.inode_table[new_inode_index].blocks[0] = new_block;

        let empty_dir_count = 0u64.to_le_bytes();
        let mut new_dir_buf = vec![0u8; block::BLOCK_SIZE];
        new_dir_buf[..size_of::<u64>()].copy_from_slice(&empty_dir_count);
        self.block_write(new_block, &new_dir_buf)?;

        let mut entry = inode::DirectoryEntry {
            inode: new_inode_index as u64,
            name: [0; inode::MAX_STRING_SIZE],
        };
        let name_bytes = dir_name.as_bytes();
        entry.name[..name_bytes.len()].copy_from_slice(name_bytes);

        parent_dir.entries.push(entry);
        parent_dir.inode_count += 1;

        self.inode_table[parent_inode_index].size += size_of::<inode::DirectoryEntry>() as u64;

        self.set_directory(parent_inode_index, &parent_dir)?;

        Ok(new_inode_index)
    }

    pub fn list_directory(&mut self, path: &str) -> Result<Vec<inode::DirectoryEntry>, Error> {
        let inode_index = self.resolve_path(path)?;
        let dir = self.directory_open(inode_index)?;
        Ok(dir.entries)
    }

    pub fn inode_read_at(&mut self, inode_idx: usize, offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        if inode_idx >= self.inode_table.len() {
            return Err(Error::InodeNotFound);
        }
        let inode = self.inode_table[inode_idx];
        if inode.used == 0 {
            return Err(Error::InodeNotFound);
        }
        if offset >= inode.size as usize {
            return Ok(0); // Offset beyond file size
        }

        let mut total_read = 0;
        while total_read < buf.len() {
            let block_idx = (offset + total_read) / block::BLOCK_SIZE;
            let block_offset = (offset + total_read) % block::BLOCK_SIZE;
            if block_idx >= inode::MAX_BLOCKS_PER_INODE as usize {
                break; // Exceeded maximum blocks per inode
            }
            if block_idx >= inode.block_count as usize {
                break; // No more blocks allocated
            }
            let mut block = [0u8; block::BLOCK_SIZE];
            self.block_read(inode.blocks[block_idx], &mut block)?;
            let to_copy = core::cmp::min(buf.len() - total_read, block::BLOCK_SIZE - block_offset);
            block_offset.checked_add(to_copy).ok_or(Error::Other("Overflow"))?;
            buf[total_read..total_read + to_copy]
                .copy_from_slice(&block[block_offset..block_offset + to_copy]);
            total_read += to_copy;
        }
        Ok(total_read)
    }

    pub fn inode_size(&mut self, inode_idx: usize) -> Result<usize, Error> {
        if inode_idx >= self.inode_table.len() {
            return Err(Error::InodeNotFound);
        }
        let inode = self.inode_table[inode_idx];
        if inode.used == 0 {
            return Err(Error::InodeNotFound);
        }
        Ok(inode.size as usize)
    }

    pub fn inode_write_at(&mut self, inode_idx: usize, offset: usize, buf: &[u8]) -> Result<usize, Error> {
        if inode_idx >= self.inode_table.len() {
            return Err(Error::InodeNotFound);
        }
        let inode = self.inode_table[inode_idx];
        if inode.used == 0 {
            return Err(Error::InodeNotFound);
        }
        let mut total_written = 0;
        while total_written < buf.len() {
            let block_idx = (offset + total_written) / block::BLOCK_SIZE;
            let block_offset = (offset + total_written) % block::BLOCK_SIZE;
            if block_idx >= inode::MAX_BLOCKS_PER_INODE as usize {
                break; // Exceeded maximum blocks per inode
            }
            if block_idx >= inode.block_count as usize {
                let new_block = self.allocate_block()?;
                self.inode_table[inode_idx].blocks[block_idx] = new_block;
                self.inode_table[inode_idx].block_count += 1;
            }
            let mut block = [0u8; block::BLOCK_SIZE];
            self.block_read(inode.blocks[block_idx], &mut block)?;
            let to_copy = core::cmp::min(buf.len() - total_written, block::BLOCK_SIZE - block_offset);
            block[block_offset..block_offset + to_copy]
                .copy_from_slice(&buf[total_written..total_written + to_copy]);
            self.block_write(inode.blocks[block_idx], &block)?;
            total_written += to_copy;
        }

        self.inode_table[inode_idx].size = core::cmp::max(
            self.inode_table[inode_idx].size,
            (offset + total_written) as u64,
        );
        Ok(total_written)
    }
    

    pub fn read_file_at(&mut self, path: &str, offset: usize, size: usize) -> Result<Vec<u8>, Error> {
        let inode_index = self.resolve_path(path)?;
        let inode = self.inode_table[inode_index];
        if inode.used == 0 || inode.inode_type != inode::InodeType::File {
            return Err(Error::InodeNotFound);
        }
        let mut file_buf = vec![0u8; size];
        self.inode_read_at(inode_index, offset, &mut file_buf)?;
        Ok(file_buf)
    }

    pub fn size_file(&mut self, path: &str) -> Result<usize, Error> {
        let inode_index = self.resolve_path(path)?;
        let inode = self.inode_table[inode_index];
        if inode.used == 0 || inode.inode_type != inode::InodeType::File {
            return Err(Error::InodeNotFound);
        }
        Ok(inode.size as usize)
    }

    pub fn write_file_at(&mut self, path: &str, offset: usize, data: &[u8]) -> Result<(), Error> {
        let inode_index = self.resolve_path(path)?;
        let inode = self.inode_table[inode_index];
        if inode.used == 0 || inode.inode_type != inode::InodeType::File {
            return Err(Error::InodeNotFound);
        }
        self.inode_write_at(inode_index, offset, data)?;
        Ok(())
    }

    pub fn delete_file(&mut self, path: &str) -> Result<(), Error> {
        let parent_path = if let Some(pos) = path.rfind('/') {
            &path[..pos]
        } else {
            return Err(Error::Other("Invalid path"));
        };
        let file_name = if let Some(pos) = path.rfind('/') {
            &path[pos + 1..]
        } else {
            path
        };

        let parent_inode_index = self.resolve_path(parent_path)?;

        if self.inode_table[parent_inode_index].inode_type != inode::InodeType::Directory {
            return Err(Error::NotADirectory);
        }

        let mut dir = self.directory_open(parent_inode_index)?;
        let mut file_inode_index = None;

        for (i, entry) in dir.entries.iter().enumerate() {
            if entry.name_as_str() == file_name {
                file_inode_index = Some(entry.inode as usize);
                dir.entries.remove(i);
                break;
            }
        }

        let file_inode_index = match file_inode_index {
            Some(idx) => idx,
            None => return Err(Error::InodeNotFound),
        };

        self.inode_table[file_inode_index].used = 0;
        for i in 0..self.inode_table[file_inode_index].block_count as usize {
            let block_index = self.inode_table[file_inode_index].blocks[i] as usize;
            self.block_bitmap.set(block_index, false);
        }
        self.inode_bitmap.set(file_inode_index, false);

        dir.inode_count -= 1;
        self.inode_table[parent_inode_index].size -= size_of::<inode::DirectoryEntry>() as u64;



        self.set_directory(parent_inode_index, &dir)?;

        Ok(())
    }

    pub fn delete_dir_entry(&mut self, path: &str) -> Result<(), Error> {
        let parent_path = if let Some(pos) = path.rfind('/') {
            &path[..pos]
        } else {
            return Err(Error::Other("Invalid path"));
        };
        let dir_name = if let Some(pos) = path.rfind('/') {
            &path[pos + 1..]
        } else {
            path
        };

        let parent_inode_index = self.resolve_path(parent_path)?;

        if self.inode_table[parent_inode_index].inode_type != inode::InodeType::Directory {
            return Err(Error::NotADirectory);
        }

        let mut dir = self.directory_open(parent_inode_index)?;
        let mut dir_inode_index = None;

        for (i, entry) in dir.entries.iter().enumerate() {
            if entry.name_as_str() == dir_name {
                dir_inode_index = Some(entry.inode as usize);
                dir.entries.remove(i);
                break;
            }
        }

        let dir_inode_index = match dir_inode_index {
            Some(idx) => idx,
            None => return Err(Error::InodeNotFound),
        };

        self.inode_table[dir_inode_index].used = 0;
        for i in 0..self.inode_table[dir_inode_index].block_count as usize {
            let block_index = self.inode_table[dir_inode_index].blocks[i] as usize;
            self.block_bitmap.set(block_index, false);
        }
        self.inode_bitmap.set(dir_inode_index, false);

        dir.inode_count -= 1;
        self.inode_table[parent_inode_index].size -= size_of::<inode::DirectoryEntry>() as u64;

        self.set_directory(parent_inode_index, &dir)?;

        Ok(())
    }

    pub fn delete(&mut self, path: &str) -> Result<(), Error> {
        let inode_index = self.resolve_path(path)?;
        let inode = self.inode_table[inode_index];
        if inode.used == 0 {
            return Err(Error::InodeNotFound);
        }

        match inode.inode_type {
            inode::InodeType::File => self.delete_file(path),
            inode::InodeType::Directory => self.delete_directory(path),
        }
    }

    pub fn delete_directory(&mut self, path: &str) -> Result<(), Error> {
        let inode_index = self.resolve_path(path)?;
        let inode = self.inode_table[inode_index];
        if inode.used == 0 || inode.inode_type != inode::InodeType::Directory {
            return Err(Error::InodeNotFound);
        }

        let dir = self.directory_open(inode_index)?;
        if !dir.entries.is_empty() {
            return Err(Error::Other("Directory not empty"));
        }
        for i in dir.entries {
            let entry_path = format!("{}/{}", path, i.name_as_str());
            self.delete(&entry_path)?;

        }

        self.delete_dir_entry(path)

    }

    pub fn unmount(mut self) -> Result<(), Error> {
        self.sync()?;
        self.device.close()
    }


}