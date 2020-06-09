use std::os::raw::c_ushort;
use std::u16;

// use async_std::io::{self};
use crate::interface::{Request, Response};
use crate::Error;
use bytes::buf::BufExt;
use bytes::*;
use libc;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream as SyncUnixStream;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct SockAddrHci {
    pub hci_family: c_ushort,
    pub hci_dev: c_ushort,
    pub hci_channel: HciChannel,
}

#[repr(u16)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
enum BtProto {
    L2CAP = 0,
    HCI = 1,
    RFCOMM = 3,
    AVDTP = 7,
}

#[repr(u16)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
enum HciChannel {
    Raw = 0,
    User = 1,
    Monitor = 2,
    Control = 3,
}

const HCI_DEV_NONE: c_ushort = 65535;

#[derive(Debug)]
pub struct ManagementSocket {
    stream: UnixStream,
}

impl ManagementSocket {
    pub fn open() -> Result<ManagementSocket, io::Error> {
        let fd: RawFd = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                BtProto::HCI as libc::c_int,
            )
        };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let addr = SockAddrHci {
            hci_family: libc::AF_BLUETOOTH as u16,
            hci_dev: HCI_DEV_NONE,
            hci_channel: HciChannel::Control,
        };

        if unsafe {
            libc::bind(
                fd,
                &addr as *const SockAddrHci as *const libc::sockaddr,
                std::mem::size_of::<SockAddrHci>() as u32,
            )
        } < 0
        {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        let stream = UnixStream::from_std(unsafe { SyncUnixStream::from_raw_fd(fd) }).unwrap();
        Ok(ManagementSocket { stream })
    }

    /// Returns either an error or the number of bytes that were sent.
    pub async fn send(&mut self, request: Request) -> Result<usize, io::Error> {
        let buf: Bytes = request.into();
        self.stream.write(&buf).await
    }

    pub async fn receive(&mut self) -> Result<Response, Error> {
        // read 6 byte header
        let mut header = [0u8; 6];
        let (r, _) = self.stream.split();
        let mut reader = BufReader::new(r);
        reader.read_exact(&mut header).await?;

        // this ugliness forces a &[u8] into [u8; 2]
        let param_size = u16::from_le_bytes([header[4], header[5]]) as usize;

        // read rest of message
        let mut body = vec![0u8; param_size];
        reader.read_exact(&mut body[..]).await?;

        // make buffer by chaining header and body
        Response::parse(BufExt::chain(&header[..], &body[..]))
    }
}
