use std::{
    io::{self, Read, Write},
    mem::swap,
    net::IpAddr,
    os::unix::net::UnixStream,
};

pub struct NftTarget {
    conn: UnixStream,
    expr: String,
    comment: bool,
}
impl NftTarget {
    pub fn new(expr: &str) -> Result<Self, anyhow::Error> {
        let (comment, expr) = match expr.strip_prefix("comment:") {
            Some(expr) => (true, expr),
            None => (false, expr),
        };
        let mut conn = UnixStream::connect("/run/nftsetd.sock")?;
        conn.write_all(expr.as_bytes())?;
        conn.write_all(b"\0")?;
        Ok(Self {
            conn,
            expr: expr.to_owned(),
            comment,
        })
    }
    pub fn reconnect(&mut self) -> Result<(), anyhow::Error> {
        let mut conn = UnixStream::connect("/run/nftsetd.sock")?;
        conn.write_all(self.expr.as_bytes())?;
        conn.write_all(b"\0")?;
        swap(&mut self.conn, &mut conn);
        Ok(())
    }
    pub fn run(
        &mut self,
        iter: impl Iterator<Item = IpAddr>,
        comment: &str,
    ) -> Result<(), anyhow::Error> {
        self.conn.write_all(b"\x01")?;
        if self.comment {
            self.conn.write_all(comment.as_bytes())?;
        }
        self.conn.write_all(b"\0")?;
        for addr in iter {
            match addr {
                IpAddr::V4(ipv4_addr) => {
                    self.conn.write_all(b"\x04")?;
                    self.conn.write_all(ipv4_addr.octets().as_slice())?;
                }
                IpAddr::V6(ipv6_addr) => {
                    self.conn.write_all(b"\x06")?;
                    self.conn.write_all(ipv6_addr.octets().as_slice())?;
                }
            }
        }
        self.conn.write_all(b"\0");
        let mut buf = [0u8; 4];
        self.conn.read_exact(&mut buf)?;
        let code = i32::from_be_bytes(buf);
        if code == 0 {
            Ok(())
        } else {
            unsafe {
                libc::__errno_location().write(code);
            }
            Err(io::Error::last_os_error().into())
        }
    }
}
