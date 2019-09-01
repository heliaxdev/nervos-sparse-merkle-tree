mod blake2b;

use crate::blake2b::new_blake2b;
use lazy_static::lazy_static;
use std::collections::HashMap;

type H256 = [u8; 32];
type TreeCache = HashMap<H256, (H256, H256)>;
const ZERO_HASH: H256 = [0u8; 32];

lazy_static! {
    static ref DEFAULT_TREE: (H256, TreeCache) = compute_default_tree();
    static ref DEFAULT_TREE_ROOT: H256 = DEFAULT_TREE.0;
}

enum Branch {
    Left,
    Right,
}

/// Iterator H256 as a path
/// iterate from left to right, from higher bit to lower bit.
struct PathIter<'a> {
    path: &'a H256,
    bit_pos: u8,
    byte_pos: u8,
}

impl<'a> From<&'a H256> for PathIter<'a> {
    fn from(path: &'a H256) -> Self {
        PathIter {
            path,
            bit_pos: 0,
            byte_pos: 0,
        }
    }
}

impl<'a> Iterator for PathIter<'a> {
    type Item = Branch;
    fn next(&mut self) -> Option<Self::Item> {
        const HIGHEST_BIT: u8 = 7;
        if let Some(byte) = self.path.get(self.byte_pos as usize) {
            let branch = if (byte >> (HIGHEST_BIT - self.bit_pos)) & 1 == 1 {
                Branch::Left
            } else {
                Branch::Right
            };
            if self.bit_pos == HIGHEST_BIT {
                self.byte_pos += 1;
                self.bit_pos = 0;
            } else {
                self.bit_pos += 1;
            }
            Some(branch)
        } else {
            None
        }
    }
}

fn merge(lhs: &H256, rhs: &H256) -> H256 {
    let mut hash = [0u8; 32];
    let mut hasher = new_blake2b();
    hasher.update(lhs);
    hasher.update(rhs);
    hasher.finalize(&mut hash);
    hash
}

/// precompute default tree
fn compute_default_tree() -> (H256, TreeCache) {
    let mut hash = ZERO_HASH.clone();
    let mut cache: TreeCache = Default::default();
    for _ in 0..256 {
        let parent = merge(&hash, &hash);
        cache.insert(parent, (hash, hash));
        hash = parent;
    }
    (hash, cache)
}

pub struct SparseMerkleTree {
    pub cache: TreeCache,
    pub root: H256,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        SparseMerkleTree::new(DEFAULT_TREE.0, DEFAULT_TREE.1.clone())
    }
}

impl SparseMerkleTree {
    pub fn new(root: H256, cache: TreeCache) -> SparseMerkleTree {
        SparseMerkleTree { root, cache }
    }

    /// update a key
    pub fn update(&mut self, key: &H256, value: H256) {
        let mut node = &self.root;
        let mut siblings = Vec::with_capacity(256);
        for branch in PathIter::from(key) {
            let parent = &self.cache[node];
            match branch {
                Branch::Left => {
                    siblings.push(parent.1.clone());
                    node = &parent.0;
                }
                Branch::Right => {
                    siblings.push(parent.0.clone());
                    node = &parent.1;
                }
            }
        }
        let mut node = value;
        for branch in PathIter::from(key).collect::<Vec<_>>().into_iter().rev() {
            let sibling = siblings.pop().expect("sibling should exsits");
            match branch {
                Branch::Left => {
                    let new_parent = merge(&node, &sibling);
                    self.cache.insert(new_parent.clone(), (node, sibling));
                    node = new_parent;
                }
                Branch::Right => {
                    let new_parent = merge(&sibling, &node);
                    self.cache.insert(new_parent.clone(), (sibling, node));
                    node = new_parent;
                }
            }
        }
        self.root = node;
    }

    /// get a value
    pub fn get(&mut self, key: &H256) -> &H256 {
        let mut node = &self.root;
        for branch in PathIter::from(key) {
            match branch {
                Branch::Left => node = &self.cache[node].0,
                Branch::Right => node = &self.cache[node].1,
            }
        }
        node
    }
    /// generate merkle proof
    pub fn gen_proof(&self, key: &H256) -> Vec<H256> {
        let mut node = &self.root;
        let mut proof = Vec::with_capacity(256);
        for branch in PathIter::from(key) {
            let parent = &self.cache[node];
            match branch {
                Branch::Left => {
                    proof.push(parent.1.clone());
                    node = &parent.0;
                }
                Branch::Right => {
                    proof.push(parent.0.clone());
                    node = &parent.1;
                }
            }
        }
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_root() {
        let tree = SparseMerkleTree::default();
        assert_eq!(tree.cache.len(), 256);
        assert_eq!(
            tree.root,
            [
                196, 132, 51, 8, 180, 167, 239, 184, 118, 169, 184, 200, 14, 177, 93, 124, 168,
                217, 185, 198, 139, 96, 205, 180, 89, 151, 241, 223, 31, 135, 83, 182
            ]
        );
    }

    #[test]
    fn test_update() {
        let mut tree = SparseMerkleTree::default();
        let mut key = [0u8; 32];
        key[31] = 1;
        let value = [7u8; 32];
        tree.update(&key, value);
        assert_eq!(tree.get(&key), &value);
    }
}