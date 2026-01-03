# Network Scanner Tools

A collection of network scanning and diagnostic utilities written in C. These tools utilize recursive bisection and multithreaded linear scanning to identify active hosts via ICMP and DNS protocols.

## Tools Overview

### 1. `bisect_ping`

An advanced ICMP (Ping) scanner designed for massive IP ranges. It uses a recursive bisection algorithm to skip empty network blocks quickly and supports a resume feature for long-running scans.

-   **Key Feature**: Traversal Index. It assigns a unique logical ID to every possible probe in the scan tree, allowing you to stop and resume a scan.
    
-   **Usage**: `sudo ./bisect_ping [OPTIONS] <CIDR>`
    
-   **Flags**:
    
    -   `-p, --probe NUM`: Resume scan from the specified probe index.
        
    -   `-m, --mask NUM`: Set the maximum depth (default: 30).
        
    -   `-t, --threads NUM`: Number of worker threads.
        

### 2. `dns_bisect`

A DNS-based network discovery tool. It probes IP ranges by sending DNS queries (Google.com A-record requests) to identify open recursive resolvers or active DNS servers.

-   **Usage**: `./dns_bisect [OPTIONS] <CIDR>`
    
-   **Flags**:
    
    -   `-l, --linear`: Switch from bisection to exhaustive linear search.
        
    -   `-p, --probe NUM`: Resume from a specific logical probe index.
        
    -   `-t, --threads NUM`: Adjust thread count for linear mode (default: 8).
        

### 3. `mini_lookup`

A lightweight, single-target DNS diagnostic tool. It crafts a raw DNS packet (including EDNS0 support) to verify if a specific server responds to queries.

-   **Usage**: `./mini_lookup <hostname> <dns_server_ip>`
    
-   **Example**: `./mini_lookup google.com 8.8.8.8`
    

## Building

The project uses CMake for compilation. It requires a C11-compliant compiler, math libraries (`-lm`), and `pthread` support.

### Compilation Steps:

1.  **Create a build directory**:
    
    ```
    mkdir build && cd build
    
    ```
    
2.  **Generate Makefiles**:
    
    ```
    cmake ..
    
    ```
    
3.  **Compile the binaries**:
    
    ```
    make
    
    ```
    

## Resume Logic (The `-p` Flag)

Both `bisect_ping` and `dns_bisect` provide a **Probe Index** in their output. Because network scans on large ranges (like a `/8` or `/16`) can take a long time or be interrupted:

1.  Note the `[Probe Index: X]` from the last status line before stopping.
    
2.  Restart the tool using the `-p X` flag.
    
3.  The tool will fast-forward the internal logic to that exact point without sending redundant packets, then continue scanning.
    

## Security & Permissions

-   **Raw Sockets**: `bisect_ping` requires `sudo` or `CAP_NET_RAW` capabilities because it uses raw sockets to craft ICMP packets.
    
-   **Network Impact**: These tools are high-speed scanners. Ensure you have explicit permission to scan target ranges to avoid being flagged by network security systems or ISPs.
