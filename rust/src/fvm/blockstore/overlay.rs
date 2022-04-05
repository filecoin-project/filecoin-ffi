use std::collections::HashMap;

use anyhow::Result;
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;

/// A blockstore with a read-only, in-memory "overlay".
///
/// 1. On get, the overlay will be checked first.
/// 2. All puts will go directly to the base blockstore.
///
/// Use this blockstore to "overlay" some pre-determined set of blocks over a real blockstore.
pub struct OverlayBlockstore<BS> {
    over: HashMap<Cid, Vec<u8>>,
    base: BS,
}

impl<BS> OverlayBlockstore<BS> {
    /// Construct a new overlay blockstore with the specified "overlay".
    pub fn new(overlay: HashMap<Cid, Vec<u8>>, base: BS) -> Self {
        OverlayBlockstore {
            over: overlay,
            base,
        }
    }
}

impl<BS> Blockstore for OverlayBlockstore<BS>
where
    BS: Blockstore,
{
    fn get(&self, k: &Cid) -> Result<Option<Vec<u8>>> {
        match self.over.get(k) {
            Some(blk) => Ok(Some(blk.clone())),
            None => self.base.get(k),
        }
    }

    fn put_keyed(&self, k: &Cid, block: &[u8]) -> Result<()> {
        self.base.put_keyed(k, block)
    }

    fn has(&self, k: &Cid) -> Result<bool> {
        Ok(self.over.contains_key(k) || self.base.has(k)?)
    }

    fn put<D>(
        &self,
        mh_code: cid::multihash::Code,
        block: &fvm_ipld_blockstore::Block<D>,
    ) -> Result<Cid>
    where
        Self: Sized,
        D: AsRef<[u8]>,
    {
        self.base.put(mh_code, block)
    }

    fn put_many<D, I>(&self, blocks: I) -> Result<()>
    where
        Self: Sized,
        D: AsRef<[u8]>,
        I: IntoIterator<Item = (cid::multihash::Code, fvm_ipld_blockstore::Block<D>)>,
    {
        self.base.put_many(blocks)
    }

    fn put_many_keyed<D, I>(&self, blocks: I) -> Result<()>
    where
        Self: Sized,
        D: AsRef<[u8]>,
        I: IntoIterator<Item = (Cid, D)>,
    {
        self.base.put_many_keyed(blocks)
    }
}
