#[cfg(feature = "acb")]
pub mod acb {
    pub mod error;
    pub mod header;
    pub mod reader;
}
#[cfg(feature = "cpk")]
pub mod cpk {
    pub mod compress {
        #[cfg(feature = "cpk_compression_layla")]
        pub mod layla;
    }
    pub mod encrypt {
        pub mod data;
        #[cfg(feature = "cpk_encryption_p5r")]
        pub mod p5r;
        #[cfg(feature = "cpk_encryption_table")]
        pub mod table;
    }
    pub mod file;
    pub mod free_list;
    pub mod reader;
    pub mod header;
    pub mod writer;
}
pub mod schema {
    pub mod columns;
    pub mod header;
    pub mod rows;
    pub mod strings;
}
pub mod utils {
    pub mod endianness;
    pub mod slice;
    #[cfg_attr(target_arch = "x86_64", path = "x86_64.rs")]
    pub mod intrinsics;
    // #[cfg_attr(target_arch = "arm", path = "arm.rs")]
    // pub mod intrinsics;
}