#![feature(generators, generator_trait)]

#[macro_use]
extern crate iold;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate time;
extern crate toml;

mod cmd;
mod config;
mod error;

use std::env;
use std::ffi::OsString;
use std::fs::{File, Metadata, create_dir, read_dir, remove_dir_all};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Generator;
use std::path::{Component, Path, PathBuf, StripPrefixError};
use std::result;
use std::str;

use iold::{EventLoop, TcpListener, TcpStream};

use cmd::{Command, TransferType};
use config::Config;
use error::Error;

const CONFIG_FILE: &'static str = "config.toml";
const MONTHS: [&'static str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
#[allow(dead_code)]
enum ResultCode {
    RestartMarkerReply = 110,
    ServiceReadInXXXMinutes = 120,
    DataConnectionAlreadyOpen = 125,
    FileStatusOk = 150,
    Ok = 200,
    CommandNotImplementedSuperfluousAtThisSite = 202,
    SystemStatus = 211,
    DirectoryStatus = 212,
    FileStatus = 213,
    HelpMessage = 214,
    SystemType = 215,
    ServiceReadyForNewUser = 220,
    ServiceClosingControlConnection = 221,
    DataConnectionOpen = 225,
    ClosingDataConnection = 226,
    EnteringPassiveMode = 227,
    UserLoggedIn = 230,
    RequestedFileActionOkay = 250,
    PATHNAMECreated = 257,
    UserNameOkayNeedPassword = 331,
    NeedAccountForLogin = 332,
    RequestedFileActionPendingFurtherInformation = 350,
    ServiceNotAvailable = 421,
    CantOpenDataConnection = 425,
    ConnectionClosed = 426,
    FileBusy = 450,
    LocalErrorInProcessing = 451,
    InsufficientStorageSpace = 452,
    UnknownCommand = 500,
    InvalidParameterOrArgument = 501,
    CommandNotImplemented = 502,
    BadSequenceOfCommands = 503,
    CommandNotImplementedForThatParameter = 504,
    NotLoggedIn = 530,
    NeedAccountForStoringFiles = 532,
    FileNotFound = 550,
    PageTypeUnknown = 551,
    ExceededStorageAllocation = 552,
    FileNameNotAllowed = 553,
}

#[allow(dead_code)]
struct Client {
    cwd: PathBuf,
    data_port: Option<u16>,
    data_stream: Option<TcpStream>,
    has_quit: bool,
    is_admin: bool,
    name: Option<String>,
    server_root: PathBuf,
    stream: TcpStream,
    transfer_type: TransferType,
    config: Config,
    waiting_password: bool,
}

impl Client {
    fn new(stream: TcpStream, server_root: PathBuf, config: Config) -> Client {
        Client {
            cwd: PathBuf::from("/"),
            data_port: None,
            data_stream: None,
            has_quit: false,
            is_admin: false,
            name: None,
            server_root,
            stream,
            transfer_type: TransferType::Ascii,
            config,
            waiting_password: false,
        }
    }

    fn is_logged(&self) -> bool {
        self.name.is_some() && self.waiting_password == false
    }

    fn handle_cmd<'a>(&'a mut self, cmd: Command) ->
        impl Generator<Yield = iold::YieldValue, Return = io::Result<()>> + 'a
    {
        static move || {
            println!("====> {:?}", cmd);
            match cmd {
                Command::Auth => await!(self.send(ResultCode::CommandNotImplemented, "Not implemented")),
                Command::CdUp if self.is_logged() => {
                    if let Some(path) = self.cwd.parent().map(Path::to_path_buf) {
                        self.cwd = path;
                        prefix_slash(&mut self.cwd);
                    }
                    await!(self.send(ResultCode::Ok, "Done"))
                }
                Command::Cwd(ref directory) if self.is_logged() => await!(self.cwd(directory)),
                Command::List(ref path) if self.is_logged() => await!(self.list(path)),
                Command::Mkd(ref path) if self.is_logged() => await!(self.mkd(path)),
                Command::NoOp => await!(self.send(ResultCode::Ok, "Doing nothing")),
                Command::Pass(ref content) if self.name.is_some() && self.waiting_password => {
                    await!(self.pass(content))
                }
                Command::Pasv if self.is_logged() => await!(self.pasv()),
                Command::Port(port) if self.is_logged() => {
                    self.data_port = Some(port);
                    let answer = format!("Data port is now {}", port);
                    await!(self.send(ResultCode::Ok, &answer))
                }
                Command::Pwd if self.is_logged() => {
                    let msg = format!("{}", self.cwd.to_str().unwrap_or("")); // small trick
                    if !msg.is_empty() {
                        let message = format!("\"{}\" ", msg);
                        await!(self.send(ResultCode::PATHNAMECreated, &message))
                    } else {
                        await!(self.send(ResultCode::FileNotFound, "No such file or directory"))
                    }
                }
                Command::Quit => await!(self.quit()),
                Command::Retr(ref file) if self.is_logged() => await!(self.retr(file)),
                Command::Rmd(ref path) if self.is_logged() => await!(self.rmd(path)),
                Command::Stor(ref file) if self.is_logged() => await!(self.stor(file)),
                Command::Syst => await!(self.send(ResultCode::Ok, "I won't tell")),
                Command::Type(typ) => {
                    self.transfer_type = typ;
                    await!(self.send(ResultCode::Ok, "Transfer type changed successfully"))
                }
                Command::Unknown(s) => {
                    let answer = format!("Not implemented: '{:?}'", s);
                    await!(self.send(ResultCode::UnknownCommand, &answer))
                },
                Command::User(ref content) => await!(self.user(content)),
                _ => await!(self.send(ResultCode::NotLoggedIn, "Please log first")),
            }
        }
    }

    async! {
    fn pass(&mut self, content: &str) -> io::Result<()> {
        let mut ok = false;
        if self.is_admin {
            ok = *content == self.config.admin.as_ref().unwrap().password;
        } else {
            for user in &self.config.users {
                if Some(&user.name) == self.name.as_ref() {
                    if user.password == *content {
                        ok = true;
                        break
                    }
                }
            }
        }
        if ok {
            self.waiting_password = false;
            let name = self.name.clone().unwrap_or(String::new());
            let answer = format!("Welcome {}", name);
            await!(self.send(ResultCode::UserLoggedIn, &answer))
        } else {
            await!(self.send(ResultCode::NotLoggedIn, "Invalid password"))
        }
    }
    }

    async! {
    fn user(&mut self, content: &str) -> io::Result<()> {
        if content.is_empty() {
            await!(self.send(ResultCode::InvalidParameterOrArgument, "Invalid username"))
        } else {
            let mut name = None;
            let mut pass_required = true;

            self.is_admin = false;
            if let Some(ref admin) = self.config.admin {
                if admin.name == content {
                    name = Some(content.to_owned());
                    pass_required = admin.password.is_empty() == false;
                    self.is_admin = true;
                }
            }
            if name.is_none() {
                for user in &self.config.users {
                    if user.name == content {
                        name = Some(content.to_owned());
                        pass_required = user.password.is_empty() == false;
                        break;
                    }
                }
            }
            if name.is_none() {
                await!(self.send(ResultCode::NotLoggedIn, "Unknown user..."))
            } else {
                self.name = name.clone();
                if pass_required {
                    self.waiting_password = true;
                    let answer = format!("Login OK, password needed for {}", content);
                    await!(self.send(ResultCode::UserNameOkayNeedPassword, &answer))
                } else {
                    self.waiting_password = false;
                    let answer = format!("Welcome {}!", content);
                    await!(self.send(ResultCode::UserLoggedIn, &answer))
                }
            }
        }
    }
    }

    fn list<'a>(&'a mut self, path: &'a Option<PathBuf>) ->
        impl Generator<Yield = iold::YieldValue, Return = io::Result<()>> + 'a
    {
        static move || {
            if self.data_stream.is_some() {
                let x = Default::default();
                let path = match *path {
                    Some(ref p) => p,
                    None => &x,
                };
                let directory = PathBuf::from(&path);
                let res = self.complete_path(directory);
                if let Ok(path) = res {
                    await!(self.send(ResultCode::DataConnectionAlreadyOpen, "Starting to list directory..."))?;
                    let mut out = vec![];
                    if path.is_dir() {
                        if let Ok(dir) = read_dir(path) {
                            for entry in dir {
                                if let Ok(entry) = entry {
                                    if self.is_admin ||
                                        entry.path() != self.server_root.join(CONFIG_FILE) {
                                            add_file_info(entry.path(), &mut out);
                                        }
                                }
                            }
                        } else {
                            await!(self.send(ResultCode::InvalidParameterOrArgument, "No such file or directory"))?;
                            return Ok(());
                        }
                    } else if self.is_admin || path != self.server_root.join(CONFIG_FILE) {
                        add_file_info(path, &mut out);
                    }
                    await!(self.send_data(out))?;
                    println!("-> and done!");
                } else {
                    await!(self.send(ResultCode::InvalidParameterOrArgument, "No such file or directory"))?;
                }
            } else {
                await!(self.send(ResultCode::ConnectionClosed, "No opened data connection"))?;
            }
            if self.data_stream.is_some() {
                self.close_data_connection();
                await!(self.send(ResultCode::ClosingDataConnection, "Transfer done"))?;
            }
            Ok(())
        }
    }

    fn close_data_connection(&mut self) {
        self.data_stream = None;
    }

    async! {
    fn pasv(&mut self) -> io::Result<()> {
        let port =
            if let Some(port) = self.data_port {
                port
            } else {
                0
            };
        if self.data_stream.is_some() {
            return await!(self.send(ResultCode::DataConnectionAlreadyOpen, "Already listening..."));
        }

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        let listener = TcpListener::bind(&addr)?;
        let port = listener.local_addr()?.port();

        let answer = format!("127,0,0,1,{},{}", port >> 8, port & 0xFF);
        await!(self.send(ResultCode::EnteringPassiveMode, &answer))?;

        println!("Waiting clients on port {}...", port);
        let (stream, _addr) = await!(listener.accept_async())?;
        println!("Accepted client");
        self.data_stream = Some(stream);

        Ok(())
    }
    }

    async! {
    fn cwd(&mut self, directory: &PathBuf) -> io::Result<()> {
        let path = self.cwd.join(&directory);
        let res = self.complete_path(path);
        if let Ok(dir) = res {
            let res = self.strip_prefix(dir);
            if let Ok(prefix) = res {
                self.cwd = prefix.to_path_buf();
                prefix_slash(&mut self.cwd);
                let answer = format!("Directory changed to \"{}\"", directory.display());
                return await!(self.send(ResultCode::RequestedFileActionOkay, &answer));
            }
        }
        await!(self.send(ResultCode::FileNotFound, "No such file or directory"))
    }
    }

    fn complete_path(&self, path: PathBuf) -> io::Result<PathBuf> {
        let directory = self.server_root.join(if path.has_root() {
            path.iter().skip(1).collect()
        } else {
            path
        });
        let dir = directory.canonicalize();
        if let Ok(ref dir) = dir {
            if !dir.starts_with(&self.server_root) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
        dir
    }

    async! {
    fn mkd(&mut self, path: &PathBuf) -> io::Result<()> {
        let path = self.cwd.join(&path);
        let parent = get_parent(path.clone());
        if let Some(parent) = parent {
            let parent = parent.to_path_buf();
            if let Ok(mut dir) = self.complete_path(parent) {
                if dir.is_dir() {
                    if let Some(filename) = get_filename(path) {
                        dir.push(filename);
                        if create_dir(dir).is_ok() {
                            return await!(self.send(ResultCode::PATHNAMECreated,
                                             "Folder successfully created!"));
                        }
                    }
                }
            }
        }
        await!(self.send(ResultCode::FileNotFound, "Couldn't create folder"))
    }
    }

    async! {
    fn rmd(&mut self, directory: &PathBuf) -> io::Result<()> {
        let path = self.cwd.join(&directory);
        if let Ok(dir) = self.complete_path(path) {
            if remove_dir_all(dir).is_ok() {
                return await!(self.send(ResultCode::RequestedFileActionOkay, "Folder successfully removed"));
            }
        }
        await!(self.send(ResultCode::FileNotFound, "Couldn't remove folder"))
    }
    }

    fn strip_prefix(&self, dir: PathBuf) -> result::Result<PathBuf, StripPrefixError> {
        dir.strip_prefix(&self.server_root).map(|p| p.to_path_buf())
    }

    fn send<'a>(&'a mut self, result: ResultCode, msg: &'a str) ->
        impl Generator<Yield = iold::YieldValue, Return = io::Result<()>> + 'a
    {
        send_cmd(&mut self.stream, result, msg)
    }

    fn send_data<'a>(&'a mut self, data: Vec<u8>) -> impl Generator<Yield = iold::YieldValue, Return = io::Result<()>>
        + 'a
    {
        static move || {
            println!("Trying to send data");
            if let Some(ref mut stream) = self.data_stream {
                println!("Sending data");
                await!(stream.write_async(&data))?; // TODO: ensure that wrote all data.
                println!("Data sent");
            }
            Ok(())
        }
    }

    async! {
    fn run(&mut self) -> io::Result<()> {
        while !self.has_quit {
            let data = await!(read_all_message(&mut self.stream));
            if data.is_empty() {
                println!("client disconnected...");
                break;
            }
            if let Ok(command) = Command::new(data) {
                await!(self.handle_cmd(command))?;
            } else {
                println!("Error with client command...");
            }
        }
        Ok(())
    }
    }

    async! {
    fn quit(&mut self) -> io::Result<()> {
        // TODO
        if self.data_stream.is_some() {
            unimplemented!();
        } else {
            await!(self.send(ResultCode::ServiceClosingControlConnection, "Closing connection..."))?;
            self.has_quit = true;
        }
        Ok(())
    }
    }

    async! {
    fn retr(&mut self, path: &PathBuf) -> io::Result<()> {
        // TODO: check if multiple data connection can be opened at the same time.
        if self.data_stream.is_some() {
            let path = self.cwd.join(path);
            if let Ok(path) = self.complete_path(path.clone()) { // TODO: still ugly clone
                if path.is_file() && (self.is_admin || path != self.server_root.join(CONFIG_FILE)) {
                    await!(self.send(ResultCode::DataConnectionAlreadyOpen, "Starting to send file..."))?;
                    let mut file = File::open(path)?;
                    let mut out = vec![];
                    // TODO: send the file chunck by chunck if it is big (if needed).
                    file.read_to_end(&mut out)?;
                    await!(self.send_data(out))?;
                    println!("-> file transfer done!");
                } else {
                    match path.to_str().ok_or_else(|| Error::Msg("No path".to_string())) {
                        Ok(p) => {
                            let answer = format!("\"{}\" doesn't exist", p);
                            await!(self.send(ResultCode::LocalErrorInProcessing, &answer))
                        },
                        Err(_) => await!(self.send(ResultCode::LocalErrorInProcessing,
                                            "path doesn't exist")),
                    }?;
                }
            } else {
                match path.to_str().ok_or_else(|| Error::Msg("No path".to_string())) {
                    Ok(p) => {
                        let answer = format!("\"{}\" doesn't exist", p);
                        await!(self.send(ResultCode::LocalErrorInProcessing, &answer))
                    },
                    Err(_) => await!(self.send(ResultCode::LocalErrorInProcessing,
                                        "path doesn't exist")),
                }?;
            }
        } else {
            await!(self.send(ResultCode::ConnectionClosed, "No opened data connection"))?;
        }
        if self.data_stream.is_some() {
            self.close_data_connection();
            await!(self.send(ResultCode::ClosingDataConnection, "Transfer done"))?;
        }
        Ok(())
    }
    }

    async! {
    fn stor(&mut self, path: &PathBuf) -> io::Result<()> {
        if self.data_stream.is_some() {
            if invalid_path(path) ||
               (!self.is_admin && *path == self.server_root.join(CONFIG_FILE)) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let path = self.cwd.join(path);
            await!(self.send(ResultCode::DataConnectionAlreadyOpen, "Starting to send file..."))?;
            let data = await!(self.receive_data())?;
            let mut file = File::create(path)?;
            file.write_all(&data)?;
            println!("-> file transfer done!");
            self.close_data_connection();
            await!(self.send(ResultCode::ClosingDataConnection, "Transfer done"))
        } else {
            await!(self.send(ResultCode::ConnectionClosed, "No opened data connection"))
        }
    }
    }

    async! {
    fn receive_data(&mut self) -> io::Result<Vec<u8>> {
        println!("Receive data");
        // NOTE: have to use this weird trick because of futures-await.
        // TODO: fix that when the lifetime stuff is improved for generators.
        Ok(if let Some(ref mut data_stream) = self.data_stream {
            let mut file_data = vec![0; 4096];
            loop {
                println!("Reading");
                await!(data_stream.read_async(&mut file_data)).expect("read async"); // TODO: handle error
                println!("***** {:?}", file_data);
            }
            file_data
        } else {
            vec![]
        })
    }
    }
}

fn read_all_message<'a>(stream: &'a mut TcpStream) -> impl Generator<Yield = iold::YieldValue, Return = Vec<u8>> + 'a {
    static move || {
        let buf = &mut [0; 1];
        let mut out = Vec::with_capacity(100);

        loop {
            match await!(stream.read_async(buf)) {
                Ok(received) if received > 0 => {
                    if out.is_empty() && buf[0] == b' ' {
                        continue
                    }
                    out.push(buf[0]);
                }
                _ => return Vec::new(),
            }
            let len = out.len();
            if len > 1 && out[len - 2] == b'\r' && out[len - 1] == b'\n' {
                out.pop();
                out.pop();
                return out;
            }
        }
    }
}

fn send_cmd<'a>(stream: &'a mut TcpStream, code: ResultCode, message: &'a str) ->
    impl Generator<Yield = iold::YieldValue, Return = io::Result<()>> + 'a
{
    static move || {
        let msg = if message.is_empty() {
            format!("{}\r\n", code as u32)
        } else {
            format!("{} {}\r\n", code as u32, message)
        };
        println!("<==== {}", msg);
        await!(stream.write_async(msg.as_bytes()))?;
        Ok(())
    }
}

fn handle_client<'a>(mut stream: TcpStream, server_root: PathBuf, config: Config) ->
    impl Generator<Yield = iold::YieldValue, Return = io::Result<()>> + 'a
{
    static move || {
        println!("new client connected!");
        await!(send_cmd(&mut stream, ResultCode::ServiceReadyForNewUser, "Welcome to this FTP server!"))?;
        let mut client = Client::new(stream, server_root, config);
        await!(client.run())
    }
}

async! {
fn server() -> io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:1234")?;
    let server_root = env::current_dir()?;
    let config = Config::new(CONFIG_FILE).expect("Error while loading config...");

    println!("Waiting for clients to connect...");
    loop {
        let stream = await!(listener.accept_async());
        match stream {
            Ok((stream, _addr)) => {
                let server_root = server_root.clone();
                let config = config.clone();
                if let Err(error) = spawn! {
                    if let Err(error) = await!(handle_client(stream, server_root, config)) {
                        println!("Error handling client: {}", error)
                    }
                } {
                    println!("Error spawning: {}", error);
                }
            }
            _ => {
                println!("A client tried to connect...")
            }
        }
    }
}
}

fn main() {
    let mut event_loop = EventLoop::new().expect("event loop");
    if let Err(error) = event_loop.run(server()) {
        println!("Error running the server: {}", error);
    }
}

fn prefix_slash(path: &mut PathBuf) {
    if !path.is_absolute() {
        *path = Path::new("/").join(&path);
    }
}

// If an error occurs when we try to get file's information, we just return and don't send its info.
fn add_file_info(path: PathBuf, out: &mut Vec<u8>) {
    let extra = if path.is_dir() { "/" } else { "" };
    let is_dir = if path.is_dir() { "d" } else { "-" };

    let meta = match ::std::fs::metadata(&path) {
        Ok(meta) => meta,
        _ => return,
    };
    let (time, file_size) = get_file_info(&meta);
    let path = match path.to_str() {
        Some(path) => match path.split("/").last() {
            Some(path) => path,
            _ => return,
        },
        _ => return,
    };
    // TODO: maybe improve how we get rights in here?
    let rights = if meta.permissions().readonly() {
        "r--r--r--"
    } else {
        "rw-rw-rw-"
    };
    let file_str = format!("{is_dir}{rights} {links} {owner} {group} {size} {month} {day} {hour}:{min} {path}{extra}\r\n",
                           is_dir=is_dir,
                           rights=rights,
                           links=1, // number of links
                           owner="anonymous", // owner name
                           group="anonymous", // group name
                           size=file_size,
                           month=MONTHS[time.tm_mon as usize],
                           day=time.tm_mday,
                           hour=time.tm_hour,
                           min=time.tm_min,
                           path=path,
                           extra=extra);
    out.extend(file_str.as_bytes());
    println!("==> {:?}", &file_str);
}

#[cfg(windows)]
fn get_file_info(meta: &Metadata) -> (time::Tm, u64) {
    use std::os::windows::prelude::*;
    (time::at(time::Timespec::new((meta.last_write_time() / 10_000_000) as i64, 0)),
    meta.file_size())
}

#[cfg(not(windows))]
fn get_file_info(meta: &Metadata) -> (time::Tm, u64) {
    use std::os::unix::prelude::*;
    (time::at(time::Timespec::new(meta.mtime(), 0)), meta.size())
}

fn get_parent(path: PathBuf) -> Option<PathBuf> {
    path.parent().map(|p| p.to_path_buf())
}

fn get_filename(path: PathBuf) -> Option<OsString> {
    path.file_name().map(|p| p.to_os_string())
}

fn invalid_path(path: &Path) -> bool {
    for component in path.components() {
        if let Component::ParentDir = component {
            return true;
        }
    }
    false
}
