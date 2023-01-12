use std::collections::HashMap;

use anyhow::Result;
use fvm3_cid::Cid as Cid3;
use fvm3_ipld_blockstore::Blockstore as Blockstore3;

use fvm2_cid::Cid as Cid2;
use fvm2_ipld_blockstore::Blockstore as Blockstore2;
use crate::fvm::engine::cid2_to_cid3;

/// A blockstore with a read-only, in-memory "overlay".
///
/// 1. On get, the overlay will be checked first.
/// 2. All puts will go directly to the base blockstore.
///
/// Use this blockstore to "overlay" some pre-determined set of blocks over a real blockstore.
pub struct OverlayBlockstore<BS> {
    over: HashMap<Cid3, Vec<u8>>,
    base: BS,
}

impl<BS> OverlayBlockstore<BS> {
    /// Construct a new overlay blockstore with the specified "overlay".
    pub fn new(overlay: HashMap<Cid3, Vec<u8>>, base: BS) -> Self {
        OverlayBlockstore {
            over: overlay,
            base,
        }
    }
}

impl<BS> Blockstore3 for OverlayBlockstore<BS>
where
    BS: Blockstore3,
{
    fn get(&self, k: &Cid3) -> Result<Option<Vec<u8>>> {
        match self.over.get(k) {
            Some(blk) => Ok(Some(blk.clone())),
            None => self.base.get(k),
        }
    }

    fn put_keyed(&self, k: &Cid3, block: &[u8]) -> Result<()> {
        self.base.put_keyed(k, block)
    }

    fn has(&self, k: &Cid3) -> Result<bool> {
        Ok(self.over.contains_key(k) || self.base.has(k)?)
    }

    fn put<D>(
        &self,
        mh_code: fvm3_cid::multihash::Code,
        block: &fvm3_ipld_blockstore::Block<D>,
    ) -> Result<Cid3>
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
        I: IntoIterator<Item = (fvm3_cid::multihash::Code, fvm3_ipld_blockstore::Block<D>)>,
    {
        self.base.put_many(blocks)
    }

    fn put_many_keyed<D, I>(&self, blocks: I) -> Result<()>
    where
        Self: Sized,
        D: AsRef<[u8]>,
        I: IntoIterator<Item = (Cid3, D)>,
    {
        self.base.put_many_keyed(blocks)
    }
}

impl<BS> Blockstore2 for OverlayBlockstore<BS>
where
    BS: Blockstore2,
{
    fn get(&self, k: &Cid2) -> Result<Option<Vec<u8>>> {
        let cid3 = cid2_to_cid3(k).unwrap();
        match self.over.get(&cid3) {
            Some(blk) => Ok(Some(blk.clone())),
            None => self.base.get(k),
        }
    }

    fn put_keyed(&self, k: &Cid2, block: &[u8]) -> Result<()> {
        self.base.put_keyed(k, block)
    }

    fn has(&self, k: &Cid2) -> Result<bool> {
        let cid3 = cid2_to_cid3(k).unwrap();
        Ok(self.over.contains_key(&cid3) || self.base.has(k)?)
    }

    fn put<D>(
        &self,
        mh_code: fvm2_cid::multihash::Code,
        block: &fvm2_ipld_blockstore::Block<D>,
    ) -> Result<Cid2>
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
        I: IntoIterator<Item = (fvm2_cid::multihash::Code, fvm2_ipld_blockstore::Block<D>)>,
    {
        self.base.put_many(blocks)
    }

    fn put_many_keyed<D, I>(&self, blocks: I) -> Result<()>
    where
        Self: Sized,
        D: AsRef<[u8]>,
        I: IntoIterator<Item = (Cid2, D)>,
    {
        self.base.put_many_keyed(blocks)
    }
}
