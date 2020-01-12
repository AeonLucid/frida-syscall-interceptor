# frida-syscall-interceptor

This project allows you to intercept syscalls on android, currently only supports Arm64. 

You need to use this in a frida typescript project. For an example on how to set one up, see [oleavr/frida-agent-example](https://github.com/oleavr/frida-agent-example).

## Issues

- The original syscall won't be called anymore if you hook it, so you are required to create a fake implementation.

## Usage

```typescript
// Add at the top.
import { hookSyscall } from 'frida-syscall-interceptor';

// Somewhere in your code.
let baseAddr = Module.findBaseAddress('libSomething.so')!;
let address = baseAddr.add('0x1234');

hookSyscall(address, new NativeCallback(function (dirfd, pathname, mode, flags) {
    let path = pathname.readCString();

    log(`Called faccessat hook`);
    log('- X0: ' + dirfd);
    log('- X1: ' + path);
    log('- X2: ' + mode);
    log('- X3: ' + flags);

    return 0;
}, 'int', ['int', 'pointer', 'int', 'int']));
```