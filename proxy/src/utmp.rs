pub fn add_entry(username: &str, pty_slave: &str, pid: libc::pid_t) {
    let mut entry: libc::utmpx = unsafe { std::mem::zeroed() };
    entry.ut_type = libc::USER_PROCESS;
    entry.ut_pid = pid;

    let line = pty_slave.strip_prefix("/dev/").unwrap_or(pty_slave);
    copy_to_c_buf(&mut entry.ut_line, line);
    copy_to_c_buf(&mut entry.ut_user, username);

    let id = if line.len() >= 4 {
        &line[line.len() - 4..]
    } else {
        line
    };
    copy_to_c_buf(&mut entry.ut_id, id);
    set_timestamp(&mut entry);

    unsafe {
        libc::setutxent();
        libc::pututxline(&entry);
        libc::endutxent();
    }
}

pub fn remove_entry(pty_slave: &str, pid: libc::pid_t) {
    let mut entry: libc::utmpx = unsafe { std::mem::zeroed() };
    entry.ut_type = libc::DEAD_PROCESS;
    entry.ut_pid = pid;

    let line = pty_slave.strip_prefix("/dev/").unwrap_or(pty_slave);
    copy_to_c_buf(&mut entry.ut_line, line);

    let id = if line.len() >= 4 {
        &line[line.len() - 4..]
    } else {
        line
    };
    copy_to_c_buf(&mut entry.ut_id, id);
    set_timestamp(&mut entry);

    unsafe {
        libc::setutxent();
        libc::pututxline(&entry);
        libc::endutxent();
    }
}

fn set_timestamp(entry: &mut libc::utmpx) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    entry.ut_tv.tv_sec = now.as_secs() as _;
    entry.ut_tv.tv_usec = now.subsec_micros() as _;
}

fn copy_to_c_buf(buf: &mut [libc::c_char], s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buf.len() - 1);
    for i in 0..len {
        buf[i] = bytes[i] as libc::c_char;
    }
}
