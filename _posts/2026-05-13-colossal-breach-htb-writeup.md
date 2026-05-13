---
layout: post
title: "Colossal Breach — HTB Writeup"
date: 2026-05-13
tags: [htb, challenge, reversing]
description: "Reverse-engineering a malicious Linux kernel keylogger module — author writeup of the Colossal Breach HTB challenge."
---

## Synopsis

This challenge revolves around analyzing a malicious Linux kernel module provided in the form of a `.ko` file, accompanied by log files. The kernel module functions as a keylogger, silently capturing and logging keystrokes entered by the user.

## Description

```
A devastating data breach has occurred, compromising one of our most secure systems. The breach has been codenamed **Colossal Breach**, reminiscent of the overwhelming force of the Colossal Titan, breaching our digital walls with unprecedented power. Our forensics team recovered a suspicious kernel object file (`.ko`) and encrypted log files from the compromised machine. Initial analysis suggests that the attackers installed a keylogging kernel module to capture sensitive credentials and exfiltrate data unnoticed.
As a member of the elite forensics squad, your mission is to analyze the kernel module and log files to uncover the attack.
```

## Enumeration

For this challenge, players are given the `.ko` file and logs of the keylogger.

![Files provided in the challenge](/assets/img/posts/colossal-breach/01-files.png)

## Solution

### [1/7] Can you identify the module's author?

The first step in analyzing the `.ko` file is to gather metadata using the `modinfo` command. This will provide valuable information about the module, including the author's name.

```bash
modinfo brainstorm.ko
```

![modinfo output showing the module author](/assets/img/posts/colossal-breach/02-modinfo.png)

**Answer:** `0xEr3n`

### [2/7] Can you determine the exact function used to register the module's notifier block?

In the disassembly of `init_module`, we can observe the function `register_keyboard_notifier()` being invoked to register the notifier block. This function is called so that the notifier block is registered as part of the initialization routine for handling keyboard events. Therefore, `register_keyboard_notifier()` is the function responsible for registering the notifier block within `init_module`.

![register_keyboard_notifier called inside init_module](/assets/img/posts/colossal-breach/03-notifier.png)

**Answer:** `register_keyboard_notifier`

### [3/7] What is the name of the function that converts keycodes to strings?

Going through all the functions, we find this uniquely named function called `keycode_to_string`.

![keycode_to_string function in the disassembly](/assets/img/posts/colossal-breach/04-keycode-func.png)

The function converts raw keyboard input into a readable format by referencing predefined keycodes in memory. It checks the input validity based on the event type stored in `rcx` and the input parameters' ranges. Depending on the value of `rcx`, it uses `snprintf` to format the output as either hexadecimal or decimal strings. Keycodes are retrieved from specific memory offsets calculated from `rdi`, allowing for the effective transformation of raw keypress data into structured output.

![Inner logic of keycode_to_string](/assets/img/posts/colossal-breach/05-keycode-details.png)

The keycodes are stored in memory and are being used to convert the keystrokes.

![Keycode table in memory](/assets/img/posts/colossal-breach/06-keycode-memory.png)

**Answer:** `keycode_to_string`

### [4/7] Can you identify any specific kernel functions or APIs that this module uses for storing the keystrokes?

Again looking into the `spy_cb` function we can identify this piece of code which is responsible for storing keystrokes.

![spy_cb function storing keystrokes via strncpy](/assets/img/posts/colossal-breach/07-spy-cb.png)

The function stores keystrokes in a buffer tracked by `buf_pos`, which indicates the current position for new data. It calculates the new position by adding the length of the incoming key representation (`rax_6`) to `buf_pos`, resulting in `rbx_1`. Before storing, it checks if `rbx_1` exceeds the buffer length (`0x3fff`) to prevent overflow; if so, it resets `rbx_1` to `rax_6`. **The function then uses `strncpy` to copy the formatted keystroke data from `var_1c` into the buffer at position `rdi_5`, ensuring the length copied is `rax_6`.** Finally, it updates `buf_pos` to reflect the new position for subsequent keystrokes.

**Answer:** `strncpy`

### [5/7] What specific files does this module create for the storage of logs? Provide the full path.

The `init_module()` function creates a debugfs file named `keys` within a directory called `spyyy`, which is used for logging keystrokes captured by the module. Debugfs is a virtual filesystem in the Linux kernel primarily used for debugging and monitoring purposes, providing an interface for kernel developers and system administrators to access kernel-related information. The `keys` file serves as a writable log, allowing the kernel module to store formatted keystroke data in real time.

![debugfs file creation in init_module](/assets/img/posts/colossal-breach/08-debugfs.png)

**Answer:** `/sys/kernel/debug/spyyy/keys`

### [6/7] What is the message printed by the module when it is imported?

We can find this by analysing the kernel logs after importing the kernel module on our own. Once we have inserted the kernel module, we can check for printed messages by the module in kernel logs using `dmesg`.

![dmesg output showing the module's print message](/assets/img/posts/colossal-breach/09-dmesg.png)

**Answer:** `w00tw00t`

### [7/7] What is the password for Adam found in the keylogger's log?

Analyzing all the functions, we can understand that the logs are being saved in the `/sys/kernel/debug/spyyy/keys` file but they are in an encrypted form.

If we pay some attention to the `spy_cb` function, there is some modification with the processed keystrokes — it first determines the length of the input string stored in `var_1c` using the `strnlen` function, which stores this length in `rax_6`. If the length is greater than zero, the function sets a pointer, `rcx_3`, to the beginning of `var_1c` and calculates `rax_7` to point to the end of the string.

A `do-while` loop is employed to iterate through each character of the string, where each character is **XORed** with a fixed key value of **`0x19`**. This operation modifies the original keystroke data, effectively obfuscating it through a bitwise XOR operation.

![XOR loop in spy_cb that obfuscates each character with 0x19](/assets/img/posts/colossal-breach/10-xor-loop.png)

In order to decrypt the logs, we can use CyberChef.

![CyberChef XOR recipe used to decode the log file](/assets/img/posts/colossal-breach/11-cyberchef.png)

Now that we have the logs, let's check them for any password related to Adam. We find the password in the logs!

![Decoded log showing Adam's password](/assets/img/posts/colossal-breach/12-password.png)

**Answer:** `supers3cur3passw0rd`