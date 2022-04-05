use std::{cell::RefCell, collections::HashMap, convert::TryFrom};

use anyhow::Result;
use cid::{
    multihash::{Code, MultihashDigest},
    Cid,
};
use fvm_ipld_blockstore::Blockstore;

use super::OverlayBlockstore;

/// A blockstore that allows putting blocks with "fake" (incorrect) CIDs. These "bad blocks" get
/// stored in a separate in-memory map and will not be written to the underlying blockstore.
///
/// This blockstore can be converted to an [`OverlayBlockstore`] by calling
/// `FakeBlockstore::finish()`, where the "fake" block map will become the `OverlayBlockstore`'s
/// "overlay".
pub struct FakeBlockstore<BS> {
    fake_blocks: RefCell<HashMap<Cid, Vec<u8>>>,
    base: BS,
}

impl<BS> FakeBlockstore<BS> {
    pub fn new(bs: BS) -> Self {
        FakeBlockstore {
            fake_blocks: RefCell::new(HashMap::new()),
            base: bs,
        }
    }
}

impl<BS> Blockstore for FakeBlockstore<BS>
where
    BS: Blockstore,
{
    fn get(&self, k: &Cid) -> Result<Option<Vec<u8>>> {
        match self.fake_blocks.borrow().get(k) {
            Some(blk) => Ok(Some(blk.clone())),
            None => self.base.get(k),
        }
    }

    fn put_keyed(&self, k: &Cid, block: &[u8]) -> Result<()> {
        if Code::try_from(k.hash().code())
            .ok()
            .map(|code| &code.digest(block) == k.hash())
            .unwrap_or_default()
        {
            self.base.put_keyed(k, block)
        } else {
            self.fake_blocks.borrow_mut().insert(*k, block.to_owned());
            Ok(())
        }
    }

    fn has(&self, k: &Cid) -> Result<bool> {
        Ok(self.fake_blocks.borrow().contains_key(k) || self.base.has(k)?)
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
        for (c, b) in blocks {
            self.put_keyed(&c, b.as_ref())?
        }
        Ok(())
    }
}

impl<BS> FakeBlockstore<BS> {
    /// Convert this "fake" blockstore into an overlay blockstore. The overlay blockstore will yield
    /// the "fake" blocks from this blockstore, but won't accept new fake blocks.
    pub fn finish(self) -> OverlayBlockstore<BS> {
        OverlayBlockstore::new(self.fake_blocks.into_inner(), self.base)
    }
}
