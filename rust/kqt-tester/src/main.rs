use std::{net::Ipv4Addr, path::PathBuf, sync::atomic::AtomicI32, thread, time::Duration};

use futures::TryStreamExt;
use rtnetlink::{LinkUnspec, LinkVeth};

use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Script for worker thread 0
    pub script0: PathBuf,

    /// Script for worker thread 1
    pub script1: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Entry guard: check self PID
    let pid = std::process::id();
    if pid != 1 {
        // We are not PID 1, fork into PID namespace

        // Creates PID namespace for child
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWPID).unwrap();

        // Respawn self in new PID namespace
        let mut cmd = std::process::Command::new(
            std::env::current_exe().expect("Failed to get current executable path"),
        );
        cmd.args(std::env::args().skip(1)); // Pass through command-line arguments
        let mut spawned = cmd.spawn().expect("Failed to spawn child process");

        // Wait for child
        let status = spawned.wait().expect("Failed to wait on child process");
        std::process::exit(status.code().unwrap_or(1));
    }

    // We are PID 1, set PR_SET_PDEATHSIG
    nix::sys::prctl::set_pdeathsig(Some(nix::sys::signal::Signal::SIGKILL)).unwrap();

    // Spwan two worker threads, moves them into individual netns
    let tid_ready = std::sync::Barrier::new(3);
    let parent_ready = std::sync::Barrier::new(3);
    let workers_ready = std::sync::Barrier::new(2);

    let tids = [AtomicI32::new(0), AtomicI32::new(0)];

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for worker in 0..2 {
            let tids = &tids;
            let threads_ready = &tid_ready;
            let parent_ready = &parent_ready;
            let workers_ready = &workers_ready;
            let script = if worker == 0 {
                &args.script0
            } else {
                &args.script1
            };

            handles.push(s.spawn(move || {
                let veth = format!("veth-kqt-test{}", worker);
                let veth_addr = Ipv4Addr::new(10, 0, 0, (worker + 1) as u8);
                // unshare into netns
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();

                // Get current TID
                let tid = nix::unistd::gettid();

                // Ordering guaranteed by barriers
                tids[worker].store(tid.as_raw(), std::sync::atomic::Ordering::Relaxed);

                println!("Worker {}[TID {}], waiting for parent", worker, tid);
                threads_ready.wait();
                parent_ready.wait();
                println!("Worker {}[TID {}], got veth", worker, tid);

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
                    rt.spawn(connection);

                    // Bring up the interface
                    handle
                        .link()
                        .set(LinkUnspec::new_with_name(&veth).up().build())
                        .execute()
                        .await
                        .unwrap();
                    println!("Worker {}[TID {}], link up", worker, tid);

                    let mut links = handle.link().get().match_name(veth).execute();
                    if let Some(link) = links.try_next().await? {
                        println!(
                            "Worker {}[TID {}], got link idx {}",
                            worker, tid, link.header.index
                        );
                        handle
                            .address()
                            .add(link.header.index, veth_addr.into(), 24)
                            .execute()
                            .await?;
                    }
                    Ok::<(), anyhow::Error>(())
                })?;

                workers_ready.wait();
                println!(
                    "Worker {}[TID {}], reaady, starting script {}",
                    worker,
                    tid,
                    script.display()
                );
                let spawned = std::process::Command::new(script)
                    .env("KQT_TESTER_NODE", worker.to_string())
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .spawn()?;
                let output = spawned.wait_with_output()?;
                println!(
                    "Worker {}[TID {}], script exited = {}",
                    worker, tid, output.status
                );

                anyhow::Ok(())
            }));
        }

        println!("Parent, waiting for workers");
        tid_ready.wait();
        println!("Parent, got worker TIDs");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (connection, handle, _) = rtnetlink::new_connection().unwrap();
            rt.spawn(connection);
            println!("Parent, spawned rtnetlink connection");

            // Creates veth pair
            handle
                .link()
                .add(LinkVeth::new("veth-kqt-test0", "veth-kqt-test1").build())
                .execute()
                .await?;

            println!("Parent, created veth pair");

            // Move each one of the veth into individual netns
            for worker in 0..2 {
                let tid = tids[worker].load(std::sync::atomic::Ordering::Relaxed);
                let name = format!("veth-kqt-test{}", worker);
                println!("Parent, {} -> netns by pid {}", name, tid);
                handle
                    .link()
                    .set(
                        LinkUnspec::new_with_name(&name)
                            .setns_by_pid(tid as u32)
                            .build(),
                    )
                    .execute()
                    .await?;
            }

            anyhow::Ok(())
        })
        .unwrap();
        parent_ready.wait();

        for handle in handles {
            handle.join().unwrap()?;
        }

        anyhow::Ok(())
    })?;

    Ok(())
}
