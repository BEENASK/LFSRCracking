use std::io;
use std::fs;
use std::io::prelude::*;
use std::convert::TryFrom;

fn main() {
    let mut done = 0;
    let png: [u8;4] = [0x89, 0x50, 0x4E, 0x47]; 
    let (mut res, mut value): (u32, u8) = (0, 0);
    let (l1, m1, l2, m2) = (12, 0b10000100000, 19, 0b100000100000000);
    let mut r1: Reg = Reg::new(l1, m1);
    let mut r2: Reg = Reg::new(l2, m2);
    let mut bytes: Vec<u8> = Vec::new();
    let enc = get_encrypted_png();
    let metadata = fs::metadata("/home/satya/Desktop/flag.enc").unwrap();
    let len = usize::try_from(metadata.len()).unwrap();

    for i in r1.tap[0]..1<<l1 {
        for j in r2.tap[0]..1<<l2 {
            r1.set(i);
            r2.set(j);
            for level in 0..len {
                res = 0;
                for k in 0..8 {
                    res += (1 << k) * (r1.next() + r2.next());
                }
                res %= 255;
                value = u8::try_from(res).unwrap();
                if level < 4 && value ^ enc[level] != png[level] {
                    break;
                }
                if level == 3 {
                    for x in {0..4} {
                        bytes.push(png[x]);
                    }
                    done = 1;
                }
                if level > 3 {
                    bytes.push(value ^ enc[level]);
                }
            }
            if done == 1 {
                let s: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        bytes.as_ptr() as *const u8,
                        bytes.len() * std::mem::size_of::<u8>()
                    )
                };
                let mut file = fs::File::create("lfsr.png").unwrap();
                file.write_all(s).unwrap();
                break;
            }
        }
        if done == 1 {
            break;
        }
    }
}
fn get_encrypted_png() -> Vec<u8> {
    let file = fs::File::open("/home/satya/Desktop/flag.enc").expect("Failed to open!");
    let mut f = io::BufReader::new(file);
    let mut buf = Vec::<u8>::new();
    while f.read_until(b'\n', &mut buf).expect("Failed to read!") != 0 {}
    buf
}

struct Reg {
    tap: [u32; 2],
    length: usize,
    value: u32,
}

impl Reg {
    fn new(length: usize, mask: u32) -> Reg {
        let mut tap: [u32; 2] = [0, 0];
        let mut i = 0;
        for x in 0..length {
            if (mask >> x & 1) == 1 {
                tap[i] = u32::try_from(x).unwrap();
                i += 1;
            }
        }
        Reg { tap, length, value: 0 }
    }
    fn view(&self) {
        for i in {0..self.length}.rev() {
        }
    }
    fn next(&mut self) -> u32 {
        let xor: u32 = ((self.value >> self.tap[0]) ^ (self.value >> self.tap[1])) & 1;
        self.value = (self.value >> 1) ^ (xor << (self.length - 1));
        self.value & 1
    }
    fn set(&mut self, value: u32) {
        self.value = value;
    }
}
