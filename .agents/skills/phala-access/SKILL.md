---
name: phala-access
description: Access Phala Cloud CVMs via SSH, copy files with SCP, stream logs, and inspect containers. Use when the user wants to SSH into a CVM, view logs, copy files to/from a CVM, or debug a running deployment.
---

# Phala Access — Logs, SSH & File Transfer

## When to use
- User wants to view CVM container logs
- User needs SSH access to a running CVM
- User wants to copy files to/from a CVM
- User needs to inspect running containers
- User wants to debug a deployment

## Prerequisites
- CVM deployed with `--dev-os` flag (required for SSH/SCP)
- SSH key registered (`phala ssh-keys list`)

## Logs

### View container logs
```bash
phala logs
phala logs <container-name>
```

### Stream logs in real-time
```bash
phala logs -f
phala logs --follow
```

### Tail last N lines
```bash
phala logs -n 100
phala logs --tail 100
```

### View logs with timestamps
```bash
phala logs -t
phala logs --timestamps
```

### Filter by time
```bash
phala logs --since 42m        # last 42 minutes
phala logs --since 2h         # last 2 hours
phala logs --until 1h         # up to 1 hour ago
```

### View VM-level logs (boot, kernel, docker-compose)
```bash
phala logs --serial
```

### View CVM stdout/stderr
```bash
phala logs --cvm-stdout
phala logs --cvm-stderr
```

### Include container stderr
```bash
phala logs --stderr
```

### Target a specific CVM
```bash
phala logs --cvm-id <CVM_ID>
```

### JSON output
```bash
phala logs --json
```

## List containers
```bash
phala ps
```
Shows all running containers in the CVM.

## Runtime configuration
```bash
phala runtime-config
```

## SSH access

### Connect to a CVM
```bash
phala ssh <CVM_ID>
phala ssh  # uses linked CVM from phala.toml
```

### SSH with verbose output
```bash
phala ssh <CVM_ID> --verbose
```

### SSH with custom timeout
```bash
phala ssh <CVM_ID> --timeout 60
```

### SSH dry run (show command without executing)
```bash
phala ssh <CVM_ID> --dry-run
```

### Port forwarding through SSH
```bash
phala ssh <CVM_ID> -- -L 8080:localhost:8080  # local forward
phala ssh <CVM_ID> -- -R 9090:localhost:9090  # remote forward
```

## File transfer (SCP)

### Copy file to CVM
```bash
phala cp ./local-file.txt my-app:/remote/path/
```

### Copy file from CVM
```bash
phala cp my-app:/remote/path/file.txt ./local-dir/
```

### Copy directory recursively
```bash
phala cp -r ./local-dir my-app:/remote/path/
```

### Copy with verbose output
```bash
phala cp -v ./file.txt my-app:/remote/path/
```

### Dry run (show SCP command)
```bash
phala cp --dry-run ./file.txt my-app:/remote/path/
```

## SSH key management

### List registered SSH keys
```bash
phala ssh-keys list
phala ssh-keys ls
```

### Add SSH key
```bash
phala ssh-keys add --name my-key --key-file ~/.ssh/id_ed25519.pub
```
Auto-detects keys from `~/.ssh/` in order: `id_ed25519.pub`, `id_rsa.pub`, `id_ecdsa.pub`.

### Import SSH keys from GitHub
```bash
phala ssh-keys import-github <github-username>
```

### Remove SSH key
```bash
phala ssh-keys remove <KEY_ID>
phala ssh-keys rm --interactive  # interactive selection
```

## Common workflows

### Debug a failing deployment
```bash
phala logs --serial --tail 50          # check VM boot
phala logs --cvm-stderr --tail 50      # check CVM errors
phala logs <container-name> -n 100     # check app logs
phala ps                               # verify containers running
```

### Live monitoring
```bash
phala logs -f -t  # stream logs with timestamps
```

### Extract build artifacts from CVM
```bash
phala cp my-app:/app/dist/output.json ./local-results/
```
