use alloc::vec::Vec;

pub const MAX_BLOCKS_PER_INODE: u64 = 12;
pub const MAX_STRING_SIZE: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum InodeType {
    File = 0,
    Directory = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Inode {
    pub used: u8,
    pub inode_type: InodeType,
    pub size: u64,
    pub block_count: u64,
    pub blocks: [u64; MAX_BLOCKS_PER_INODE as usize],
}

impl Default for Inode {
    fn default() -> Self {
        Inode {
            used: 0,
            inode_type: InodeType::File,
            size: 0,
            block_count: 0,
            blocks: [0; MAX_BLOCKS_PER_INODE as usize],
        }
    }
}


#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DirectoryEntry {
    pub inode: u64,
    pub name: [u8; MAX_STRING_SIZE],
}

impl DirectoryEntry {
    pub fn name_as_str(&self) -> &str {
        let end = self.name.iter().position(|&c| c == 0).unwrap_or(MAX_STRING_SIZE);
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub inode_count: u64,
    pub entries: Vec<DirectoryEntry>
}

impl Directory {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.inode_count.to_le_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.inode.to_le_bytes());
            bytes.extend_from_slice(&entry.name);
        }
        bytes
    }
}