use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
};

pub mod cipp;
pub mod generic;

pub const VERSION: &str = "1.0.1";

pub fn read_lines<P>(filename: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);

    reader.lines().collect()
}
