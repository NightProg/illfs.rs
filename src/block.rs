use alloc::vec;
use alloc::vec::Vec;

pub const BLOCK_SIZE: usize = 4096; // Size of a block in bytes
pub const ILLFS_MAGIC: u64 = 0x494C4C4653;
pub const ILLFS_VERSION: u64 = 1;


#[repr(C, packed)]
pub struct Superblock {
    pub magic: u64,
    pub version: u64,
    pub block_size: u64,
    pub block_count: u64,
    pub inode_count: u64,
    pub blocks_start: u64,
    pub blocks_bitmap_start: u64,
    pub blocks_bitmap_blocks: u64,
    pub inode_bitmap_start: u64,
    pub inode_bitmap_blocks: u64,
    pub inodes_table_start: u64,
    pub inodes_table_blocks: u64,
}

pub struct BitMap {
    pub bits: Vec<u8>,
}

impl BitMap {
    pub fn new(size: usize) -> Self {
        BitMap {
            bits: vec![0; size.div_ceil(8)],
        }
    }

    pub fn set(&mut self, index: usize, value: bool) {
        if value {
            let byte_index = index / 8;
            let bit_index = index % 8;
            self.bits[byte_index] |= 1 << bit_index;
        } else {
            let byte_index = index / 8;
            let bit_index = index % 8;
            self.bits[byte_index] &= !(1 << bit_index);
        }
    }

    pub fn get(&self, index: usize) -> bool {
        let byte_index = index / 8;
        let bit_index = index % 8;
        (self.bits[byte_index] & (1 << bit_index)) != 0
    }
}