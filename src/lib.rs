#![no_std]

pub mod block;
pub mod inode;

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;


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
        let superblock: block::Superblock = unsafe { core::ptr::read(superblock_buf.as_ptr() as *const _) };

        if superblock.magic != block::ILLFS_MAGIC || superblock.version != block::ILLFS_VERSION {
            return Err(Error::InvalidSuperblock);
        }

        // Load block bitmap
        let mut block_bitmap_buf = vec![0u8; (superblock.blocks_bitmap_blocks as usize) * block::BLOCK_SIZE];
        device.read(superblock.blocks_bitmap_start * block::BLOCK_SIZE as u64, &mut block_bitmap_buf)?;
        let block_bitmap = block::BitMap { bits: block_bitmap_buf };

        // Load inode bitmap
        let mut inode_bitmap_buf = vec![0u8; (superblock.inode_bitmap_blocks as usize) * block::BLOCK_SIZE];
        device.read(superblock.inode_bitmap_start * block::BLOCK_SIZE as u64, &mut inode_bitmap_buf)?;
        let inode_bitmap = block::BitMap { bits: inode_bitmap_buf };

        // Load inode table
        let mut inode_table = Vec::with_capacity(superblock.inode_count as usize);
        for i in 0..superblock.inode_count {
            let mut inode_buf = [0u8; size_of::<inode::Inode>()];
            device.read(
                superblock.inodes_table_start * block::BLOCK_SIZE as u64 + i * size_of::<inode::Inode>() as u64,
                &mut inode_buf,
            )?;
            let inode: inode::Inode = unsafe { core::ptr::read(inode_buf.as_ptr() as *const _) };
            inode_table.push(inode);
        }

        Ok(IllFs {
            device,
            superblock,
            block_bitmap,
            inode_bitmap,
            inode_table,
        })
    }

    pub fn make_filesystem(mut device: D) -> Result<Self, Error> {
        let size = device.size();
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
        let mut inode_table: Vec<inode::Inode> = Vec::with_capacity(superblock.inode_count as usize);
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
        let block_bitmap_buf: &[u8] = &self.block_bitmap.bits;
        self.device.write(
            self.superblock.blocks_bitmap_start * block::BLOCK_SIZE as u64,
            block_bitmap_buf,
        )?;
        let inode_bitmap_buf: &[u8] = &self.inode_bitmap.bits;
        self.device.write(
            self.superblock.inode_bitmap_start * block::BLOCK_SIZE as u64,
            inode_bitmap_buf,
        )?;
        self.device.write(
            self.superblock.inodes_table_start * block::BLOCK_SIZE as u64,
            unsafe {
                core::slice::from_raw_parts(
                    self.inode_table.as_ptr() as *const u8,
                    self.inode_table.len() * size_of::<inode::Inode>(),
                )
            },
        )?;
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
        let mut dir_buf = vec![0u8; inode.size as usize];
        for i in 0..inode.block_count {
            let block_index = inode.blocks[i as usize];
            let offset = i as usize * block::BLOCK_SIZE;
            self.block_read(block_index, &mut dir_buf[offset..offset + block::BLOCK_SIZE])?;
        }
        let dir: inode::Directory = unsafe { core::ptr::read(dir_buf.as_ptr() as *const _) };
        Ok(dir)
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
        for i in 0..self.superblock.block_count as usize {
            if !self.block_bitmap.get(i) {
                self.block_bitmap.set(i, true);
                return Ok(i as u64);
            }
        }
        Err(Error::NoSpace)
    }

    pub fn allocate_inode(&mut self) -> Result<usize, Error> {
        for i in 0..self.superblock.inode_count as usize {
            if !self.inode_bitmap.get(i) {
                self.inode_bitmap.set(i, true);
                return Ok(i);
            }
        }
        Err(Error::NoSpace)
    }

    pub fn create_file(&mut self, path: &str) -> Result<usize, Error> {
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

        let new_inode_index = self.allocate_inode()?;
        let new_inode = &mut self.inode_table[new_inode_index];
        new_inode.used = 1;
        new_inode.inode_type = inode::InodeType::File;
        new_inode.size = 0;
        new_inode.block_count = 0;

        let mut dir = self.directory_open(parent_inode_index)?;
        let mut entry = inode::DirectoryEntry {
            inode: new_inode_index as u64,
            name: [0; inode::MAX_STRING_SIZE],
        };
        let name_bytes = file_name.as_bytes();
        if name_bytes.len() >= inode::MAX_STRING_SIZE {
            return Err(Error::Other("File name too long"));
        }
        entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
        dir.entries.push(entry);
        self.inode_table[parent_inode_index].size += size_of::<inode::DirectoryEntry>() as u64;
        self.inode_table[parent_inode_index].block_count += 1;

        Ok(new_inode_index)
    }

    pub fn create_directory(&mut self, path: &str) -> Result<usize, Error> {
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
        let new_block = self.allocate_block()?;
        let new_inode_index = self.allocate_inode()?;
        let new_inode = &mut self.inode_table[new_inode_index];
        new_inode.used = 1;
        new_inode.inode_type = inode::InodeType::Directory;
        new_inode.size = size_of::<u64>() as u64;
        new_inode.block_count = 1;
        new_inode.blocks[0] = new_block;

        let root_dir_buf = 0u64.to_le_bytes();
        self.block_write(new_block, &root_dir_buf)?;


        let mut dir = self.directory_open(parent_inode_index)?;
        let mut entry = inode::DirectoryEntry {
            inode: new_inode_index as u64,
            name: [0; inode::MAX_STRING_SIZE],
        };
        let name_bytes = dir_name.as_bytes();
        if name_bytes.len() >= inode::MAX_STRING_SIZE {
            return Err(Error::Other("Directory name too long"));
        }
        entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
        dir.entries.push(entry);
        self.inode_table[parent_inode_index].size += size_of::<inode::DirectoryEntry>() as u64;
        self.inode_table[parent_inode_index].block_count += 1;

        Ok(new_inode_index)
    }

    pub fn list_directory(&mut self, path: &str) -> Result<Vec<inode::DirectoryEntry>, Error> {
        let inode_index = self.resolve_path(path)?;
        let dir = self.directory_open(inode_index)?;
        Ok(dir.entries)
    }

    pub fn inode_read(&mut self, inode_idx: usize, buf: &mut [u8]) -> Result<usize, Error> {
        if inode_idx >= self.inode_table.len() {
            return Err(Error::InodeNotFound);
        }
        let inode = self.inode_table[inode_idx];
        if inode.used == 0 {
            return Err(Error::InodeNotFound);
        }
        let mut total_read = 0;
        let mut remaining = inode.size as usize;

        for i in 0..inode.block_count as usize {
            let mut block_buf = [0u8; block::BLOCK_SIZE];
            let block_index = inode.blocks[i];
            self.block_read(block_index, &mut block_buf)?;

            let to_read = core::cmp::min(remaining, block::BLOCK_SIZE);
            buf[total_read..total_read + to_read].copy_from_slice(&block_buf[..to_read]);
            total_read += to_read;
            remaining -= to_read;

            if remaining == 0 {
                break;
            }
        }

        Ok(total_read)
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
        let mut remaining = core::cmp::min(buf.len(), (inode.size as usize) - offset);
        let mut current_offset = offset;

        while remaining > 0 {
            let block_idx = current_offset / block::BLOCK_SIZE;
            let block_offset = current_offset % block::BLOCK_SIZE;
            let block_index = inode.blocks[block_idx];

            let mut block_buf = [0u8; block::BLOCK_SIZE];
            self.block_read(block_index, &mut block_buf)?;

            let to_read = core::cmp::min(remaining, block::BLOCK_SIZE - block_offset);
            buf[total_read..total_read + to_read]
                .copy_from_slice(&block_buf[block_offset..block_offset + to_read]);

            total_read += to_read;
            current_offset += to_read;
            remaining -= to_read;
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

    pub fn inode_write(&mut self, inode_idx: usize, buf: &[u8]) -> Result<usize, Error> {
        if inode_idx >= self.inode_table.len() {
            return Err(Error::InodeNotFound);
        }
        let inode = self.inode_table[inode_idx];
        if inode.used == 0 {
            return Err(Error::InodeNotFound);
        }
        let mut total_written = 0;
        let mut remaining = buf.len();

        for i in 0..inode.block_count as usize {
            let to_write = core::cmp::min(remaining, block::BLOCK_SIZE);
            let block_index = inode.blocks[i];

            let mut block_buf = [0u8; block::BLOCK_SIZE];
            block_buf[..to_write].copy_from_slice(&buf[total_written..total_written + to_write]);
            self.block_write(block_index, &block_buf)?;

            total_written += to_write;
            remaining -= to_write;

            if remaining == 0 {
                break;
            }
        }

        self.inode_table[inode_idx].size = total_written as u64;

        Ok(total_written)
    }

    pub fn inode_write_at(&mut self, inode_idx: usize, offset: usize, buf: &[u8]) -> Result<usize, Error> {
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

        let mut total_written = 0;
        let mut remaining = core::cmp::min(buf.len(), (inode.size as usize) - offset);
        let mut current_offset = offset;

        while remaining > 0 {
            let block_idx = current_offset / block::BLOCK_SIZE;
            let block_offset = current_offset % block::BLOCK_SIZE;
            let block_index = inode.blocks[block_idx];

            let mut block_buf = [0u8; block::BLOCK_SIZE];
            self.block_read(block_index, &mut block_buf)?;

            let to_write = core::cmp::min(remaining, block::BLOCK_SIZE - block_offset);
            block_buf[block_offset..block_offset + to_write]
                .copy_from_slice(&buf[total_written..total_written + to_write]);

            self.block_write(block_index, &block_buf)?;

            total_written += to_write;
            current_offset += to_write;
            remaining -= to_write;
        }

        Ok(total_written)
    }

    pub fn read_file(&mut self,path: &str) -> Result<Vec<u8>, Error> {
        let inode_index = self.resolve_path(path)?;
        let inode = self.inode_table[inode_index];
        if inode.used == 0 || inode.inode_type != inode::InodeType::File {
            return Err(Error::InodeNotFound);
        }
        let mut file_buf = vec![0u8; inode.size as usize];
        self.inode_read(inode_index, &mut file_buf)?;
        Ok(file_buf)
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

    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), Error> {
        let inode_index = self.resolve_path(path)?;
        let inode = self.inode_table[inode_index];
        if inode.used == 0 || inode.inode_type != inode::InodeType::File {
            return Err(Error::InodeNotFound);
        }
        self.inode_write(inode_index, data)?;
        Ok(())
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

    pub fn unmount(mut self) -> Result<(), Error> {
        self.sync()?;
        self.device.close()
    }


}