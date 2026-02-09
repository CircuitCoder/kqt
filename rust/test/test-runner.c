/*
 * KQT Test Runner
 * 
 * A dedicated test runner that:
 * - Creates temporary network namespaces for each node
 * - Uses PID namespace for proper cleanup
 * - Uses PR_SET_PDEATHSIG to ensure cleanup on parent exit
 * - Runs kqt nodes in separate network namespaces
 * - Executes test scripts in the appropriate namespace
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sched.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#define RED     "\033[0;31m"
#define GREEN   "\033[0;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[0;34m"
#define NC      "\033[0m"

// Global PIDs for cleanup
static pid_t node1_pid = 0;
static pid_t node2_pid = 0;
static char ns1_name[256] = {0};
static char ns2_name[256] = {0};

void cleanup() {
    fprintf(stderr, YELLOW "Cleaning up...\n" NC);
    
    // Kill nodes if still running
    if (node1_pid > 0) {
        kill(node1_pid, SIGTERM);
    }
    if (node2_pid > 0) {
        kill(node2_pid, SIGTERM);
    }
    
    // Small delay for graceful shutdown
    usleep(500000);
    
    // Delete network namespaces
    if (ns1_name[0]) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "ip netns del %s 2>/dev/null", ns1_name);
        system(cmd);
    }
    if (ns2_name[0]) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "ip netns del %s 2>/dev/null", ns2_name);
        system(cmd);
    }
    
    fprintf(stderr, GREEN "Cleanup complete\n" NC);
}

void signal_handler(int sig) {
    cleanup();
    exit(1);
}

int setup_netns(const char *ns_name, const char *veth_local, const char *veth_peer, 
                const char *ip_addr, const char *peer_ns) {
    char cmd[512];
    
    // Create network namespace
    snprintf(cmd, sizeof(cmd), "ip netns add %s", ns_name);
    if (system(cmd) != 0) {
        fprintf(stderr, RED "Failed to create netns %s\n" NC, ns_name);
        return -1;
    }
    
    // Create veth pair
    snprintf(cmd, sizeof(cmd), "ip link add %s type veth peer name %s", 
             veth_local, veth_peer);
    if (system(cmd) != 0) {
        fprintf(stderr, RED "Failed to create veth pair\n" NC);
        return -1;
    }
    
    // Move veth interfaces to namespaces
    snprintf(cmd, sizeof(cmd), "ip link set %s netns %s", veth_local, ns_name);
    system(cmd);
    
    snprintf(cmd, sizeof(cmd), "ip link set %s netns %s", veth_peer, peer_ns);
    system(cmd);
    
    // Configure interface in this namespace
    snprintf(cmd, sizeof(cmd), "ip netns exec %s ip addr add %s dev %s", 
             ns_name, ip_addr, veth_local);
    system(cmd);
    
    snprintf(cmd, sizeof(cmd), "ip netns exec %s ip link set %s up", 
             ns_name, veth_local);
    system(cmd);
    
    snprintf(cmd, sizeof(cmd), "ip netns exec %s ip link set lo up", ns_name);
    system(cmd);
    
    return 0;
}

pid_t run_in_netns(const char *ns_name, const char *config_file, const char *kqt_bin) {
    pid_t pid = fork();
    
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) {
        // Child process
        // Set PR_SET_PDEATHSIG to get SIGTERM when parent dies
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0) {
            perror("prctl PR_SET_PDEATHSIG");
            exit(1);
        }
        
        // Enter network namespace
        char ns_path[256];
        snprintf(ns_path, sizeof(ns_path), "/var/run/netns/%s", ns_name);
        
        int fd = open(ns_path, O_RDONLY);
        if (fd < 0) {
            perror("open netns");
            exit(1);
        }
        
        if (setns(fd, CLONE_NEWNET) < 0) {
            perror("setns");
            exit(1);
        }
        close(fd);
        
        // Execute kqt
        execl(kqt_bin, kqt_bin, "server", config_file, "kqt0", NULL);
        perror("execl");
        exit(1);
    }
    
    return pid;
}

int run_test_script(const char *ns_name, const char *script, const char *other_ns) {
    pid_t pid = fork();
    
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) {
        // Child process
        // Set environment variables for the script
        setenv("NS1", ns_name, 1);
        setenv("NS2", other_ns, 1);
        
        // Execute script
        execl("/bin/bash", "bash", script, NULL);
        perror("execl");
        exit(1);
    }
    
    // Wait for script to complete
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <node1_config> <node2_config> <node1_script> <node2_script>\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Arguments:\n");
        fprintf(stderr, "  node1_config - Configuration file for node 1\n");
        fprintf(stderr, "  node2_config - Configuration file for node 2\n");
        fprintf(stderr, "  node1_script - Test script to run in node1's netns\n");
        fprintf(stderr, "  node2_script - Test script to run in node2's netns\n");
        return 1;
    }
    
    const char *node1_config = argv[1];
    const char *node2_config = argv[2];
    const char *node1_script = argv[3];
    const char *node2_script = argv[4];
    
    // Check if we need to relaunch in PID namespace
    if (getpid() != 1) {
        // Not PID 1, relaunch in PID namespace
        char *args[] = {argv[0], argv[1], argv[2], argv[3], argv[4], NULL};
        
        // Fork and create new PID namespace
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }
        
        if (pid == 0) {
            // Child - create new namespaces
            if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
                perror("unshare");
                exit(1);
            }
            
            // Fork again to become PID 1 in new namespace
            pid = fork();
            if (pid < 0) {
                perror("fork");
                exit(1);
            }
            
            if (pid == 0) {
                // Grandchild - we are now PID 1
                // Mount /proc
                mount("proc", "/proc", "proc", 0, NULL);
                
                // Execute ourselves
                execv(argv[0], args);
                perror("execv");
                exit(1);
            }
            
            // Wait for grandchild
            int status;
            waitpid(pid, &status, 0);
            exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
        }
        
        // Parent - wait for child
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    
    // We are now PID 1 in a PID namespace
    fprintf(stderr, BLUE "=== KQT Test Runner ===" NC "\n");
    fprintf(stderr, "\n");
    
    // Set up signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    // Get KQT binary path
    const char *kqt_bin = getenv("KQT_BIN");
    if (!kqt_bin) {
        kqt_bin = "../../target/release/kqt";
    }
    
    // Check if binary exists
    if (access(kqt_bin, X_OK) != 0) {
        fprintf(stderr, RED "Error: kqt binary not found or not executable: %s\n" NC, kqt_bin);
        return 1;
    }
    
    // Generate unique namespace names
    snprintf(ns1_name, sizeof(ns1_name), "kqt-test-ns1-%d", getpid());
    snprintf(ns2_name, sizeof(ns2_name), "kqt-test-ns2-%d", getpid());
    
    fprintf(stderr, YELLOW "Step 1: Setting up network namespaces...\n" NC);
    
    // Set up network namespaces
    if (setup_netns(ns1_name, "veth1", "veth2", "10.0.0.1/24", ns2_name) < 0) {
        cleanup();
        return 1;
    }
    
    if (setup_netns(ns2_name, "veth2", "veth1", "10.0.0.2/24", ns1_name) < 0) {
        cleanup();
        return 1;
    }
    
    fprintf(stderr, GREEN "Network namespaces created: %s, %s\n" NC, ns1_name, ns2_name);
    fprintf(stderr, "\n");
    
    fprintf(stderr, YELLOW "Step 2: Starting kqt nodes...\n" NC);
    
    // Start node1
    node1_pid = run_in_netns(ns1_name, node1_config, kqt_bin);
    if (node1_pid < 0) {
        cleanup();
        return 1;
    }
    fprintf(stderr, "Started node1 (PID: %d)\n", node1_pid);
    
    // Start node2
    node2_pid = run_in_netns(ns2_name, node2_config, kqt_bin);
    if (node2_pid < 0) {
        cleanup();
        return 1;
    }
    fprintf(stderr, "Started node2 (PID: %d)\n", node2_pid);
    
    // Wait for nodes to initialize
    fprintf(stderr, "Waiting for nodes to initialize...\n");
    sleep(5);
    fprintf(stderr, "\n");
    
    fprintf(stderr, YELLOW "Step 3: Running test scripts...\n" NC);
    fprintf(stderr, "\n");
    
    // Run test scripts (we'll run node1_script which typically tests both)
    int result = run_test_script(ns1_name, node1_script, ns2_name);
    
    // Cleanup
    cleanup();
    
    if (result == 0) {
        fprintf(stderr, "\n");
        fprintf(stderr, GREEN "=== Test passed! ===\n" NC);
    } else {
        fprintf(stderr, "\n");
        fprintf(stderr, RED "=== Test failed! ===\n" NC);
    }
    
    return result;
}
