#!/usr/bin/env python3
import os
import subprocess
import re

def check_sudo():
    print("> Press Enter When Asked For Sudo Passwd")
    result = subprocess.run(['sudo', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True, result.stdout.decode()
    else:
        return False, "No sudo privileges or requires a password."

def check_suid_sgid():
    print("[+] Searching for SUID/SGID binaries...")
    find_command = 'find / -type f -perm -4000 -o -perm -2000 -exec ls -la {} ;'
    result = subprocess.run(find_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0 and result.stdout.decode().strip():
        return True, result.stdout.decode()
    return False, "No SUID/SGID binaries found."

def check_writable_files():
    print("[+] Searching for world-writable files...")
    find_command = 'find / -type f -perm -002 -exec ls -la {} ;'
    result = subprocess.run(find_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0 and result.stdout.decode().strip():
        return True, result.stdout.decode()
    return False, "No world-writable files found."

def check_kernel_version():
    try:
        result = subprocess.run(['uname', '-r'], stdout=subprocess.PIPE)
        kernel_version = result.stdout.decode().strip()
        print(f"[+] Kernel version: {kernel_version}")
        vulnerable_kernels = ["4.4.0", "5.0.0", "3.10.0-327", "4.15.0"]
        for vuln_kernel in vulnerable_kernels:
            if vuln_kernel in kernel_version:
                return True, "[+] This kernel version might be vulnerable!"
        return False, "[-] Kernel version is not listed as vulnerable."
    except FileNotFoundError:
        return False, "[-] uname command not found."

def check_docker():
    print("[+] Checking for Docker misconfigurations...")
    try:
        result = subprocess.run(['docker', 'info'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            docker_info = result.stdout.decode()
            if "security" in docker_info.lower():
                return True, "[+] Docker might be misconfigured, review security settings!"
            return False, "[-] Docker is installed, but no security issues found."
        else:
            return False, "[-] Docker is not installed or not running."
    except FileNotFoundError:
        return False, "[-] Docker is not installed."

def check_apache():
    print("[+] Checking for Apache misconfigurations...")
    try:
        result = subprocess.run(['apache2ctl', '-V'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            apache_info = result.stdout.decode()
            print("[+] Apache is installed.")
            apache_version_match = re.search(r'Apache/([0-9.]+)', apache_info)
            if apache_version_match:
                apache_version = apache_version_match.group(1)
                vulnerable_versions = ["2.4.0", "2.2.15"]
                if any(vuln in apache_version for vuln in vulnerable_versions):
                    return True, f"[+] Apache version {apache_version} is vulnerable, consider patching it."
            return False, "[-] Apache version is not vulnerable."
        else:
            return False, "[-] Apache is not installed or not running."
    except FileNotFoundError:
        return False, "[-] Apache is not installed."

def check_cron_jobs():
    print("[+] Checking for potential exploitable cron jobs...")
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly']
    cron_output = ""
    found_cron_jobs = False
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            result = subprocess.run(['ls', '-la', cron_dir], stdout=subprocess.PIPE)
            if result.returncode == 0 and result.stdout.decode().strip():
                found_cron_jobs = True
                cron_output += f"Cron jobs found in {cron_dir}:\n{result.stdout.decode()}\n"
    if found_cron_jobs:
        return True, cron_output
    return False, "[-] No cron jobs found."

def check_sensitive_files():
    print("[+] Checking for sensitive files with weak permissions...")
    sensitive_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/group']
    sensitive_file_output = ""
    found_sensitive_files = False
    for file in sensitive_files:
        if os.path.exists(file):
            perms = oct(os.stat(file).st_mode)[-3:]
            if perms == '777' or perms == '666':
                sensitive_file_output += f"[+] {file} is world-writable or group-writable!\n"
                found_sensitive_files = True
            else:
                sensitive_file_output += f"[-] {file} has appropriate permissions.\n"
        else:
            sensitive_file_output += f"[-] {file} does not exist.\n"
    
    if found_sensitive_files:
        return True, sensitive_file_output
    return False, "[-] No weak permissions on sensitive files."

def check_ssh_keys():
    print("[+] Checking for potentially weak SSH key configurations...")
    ssh_dir = "/home"
    result = subprocess.run(['find', ssh_dir, '-type', 'f', '-name', 'authorized_keys'], stdout=subprocess.PIPE)
    if result.returncode == 0:
        ssh_keys_output = ""
        for keyfile in result.stdout.decode().splitlines():
            if os.path.exists(keyfile):
                perms = oct(os.stat(keyfile).st_mode)[-3:]
                if perms != '600':
                    ssh_keys_output += f"[+] {keyfile} has weak permissions!\n"
                else:
                    ssh_keys_output += f"[-] {keyfile} has appropriate permissions.\n"
        return True, ssh_keys_output
    return False, "[-] No SSH authorized_keys found."

def print_credits():
    print("""
    Privilege Escalation Script - Credits
    ------------------------------------
    Developed by: 𝐇𝟒𝐜𝐤𝐌𝐞𝐃𝐚𝐃𝐝𝐲
    GitHub: https://github.com/H4ckMeDaDdy
    License: MIT License
    """)

def main():
    print_credits()
    print("[+] Starting Privilege Escalation Script...\n")
    
    findings = {
        "sudo": check_sudo(),
        "suid_sgid": check_suid_sgid(),
        "writable_files": check_writable_files(),
        "kernel_version": check_kernel_version(),
        "docker": check_docker(),
        "apache": check_apache(),
        "cron_jobs": check_cron_jobs(),
        "sensitive_files": check_sensitive_files(),
        "ssh_keys": check_ssh_keys()
    }

    summary = []
    
    print("\n[+] Detailed findings:")
    for key, (found, details) in findings.items():
        print(details)
        if found:
            summary.append(f"[+] {key.replace('_', ' ').title()} is potentially exploitable.")
        else:
            summary.append(f"[-] {key.replace('_', ' ').title()} is not exploitable or misconfigured.")

    print("\n[+] Summary of Privilege Escalation Checks:")
    for line in summary:
        print(line)

if __name__ == '__main__':

    main()

