import { SyscallCallback } from "./callback";

let callbacks: SyscallCallback[] = [];

export function hookSyscall(syscallAddress: NativePointer, callback: NativeCallback) {
    const address = syscallAddress.sub(12);
    const instructions = address.readByteArray(12);

    if (instructions == null) {
        throw new Error(`Unable to read instructions at address ${address}.`);
    }

    Memory.patchCode(address, 16, function (code) {
        let writer = new Arm64Writer(code, { pc: address });
        writer.putBranchAddress(createCallback(callback, instructions, address.add(16), syscallAddress));
        writer.flush();
    });
}

function createCallback(callback: NativeCallback, instructions: ArrayBuffer, retAddress: NativePointer, syscallAddress: NativePointer) {
    // Create custom instructions.
    let frida = Memory.alloc(Process.pageSize);

    Memory.patchCode(frida, Process.pageSize, function (code) {
        let writer = new Arm64Writer(code, { pc: frida });

        // Restore argument instructions.
        writer.putBytes(instructions);

        // Push all registers except x0.
        writer.putPushRegReg('x15', 'x1');
        writer.putPushRegReg('x2', 'x3');
        writer.putPushRegReg('x4', 'x5');
        writer.putPushRegReg('x6', 'x7');
        writer.putPushRegReg('x8', 'x9');
        writer.putPushRegReg('x10', 'x11');
        writer.putPushRegReg('x12', 'x13');
        writer.putPushRegReg('x14', 'x15');
        writer.putPushRegReg('x16', 'x17');
        writer.putPushRegReg('x18', 'x19');
        writer.putPushRegReg('x20', 'x21');
        writer.putPushRegReg('x22', 'x23');
        writer.putPushRegReg('x24', 'x25');
        writer.putPushRegReg('x26', 'x27');
        writer.putPushRegReg('x28', 'x29');
        writer.putInstruction(0xd53b420f);
        writer.putPushRegReg('x30', 'x15');

        // Call native.
        writer.putLdrRegAddress('x16', callback);
        writer.putBlrReg('x16');

        // Pop all registers, except x0, so x0 from native call gets used.
        writer.putPopRegReg('x30', 'x15');
        writer.putInstruction(0xd51b420f);
        writer.putPopRegReg('x28', 'x29');
        writer.putPopRegReg('x26', 'x27');
        writer.putPopRegReg('x24', 'x25');
        writer.putPopRegReg('x22', 'x23');
        writer.putPopRegReg('x20', 'x21');
        writer.putPopRegReg('x18', 'x19');
        writer.putPopRegReg('x16', 'x17');
        writer.putPopRegReg('x14', 'x15');
        writer.putPopRegReg('x12', 'x13');
        writer.putPopRegReg('x10', 'x11');
        writer.putPopRegReg('x8', 'x9');
        writer.putPopRegReg('x6', 'x7');
        writer.putPopRegReg('x4', 'x5');
        writer.putPopRegReg('x2', 'x3');
        writer.putPopRegReg('x15', 'x1');

        // Call syscall.
        // writer.putInstruction(0xd4000001);

        writer.putBranchAddress(retAddress);
        writer.flush();
    });

    // Store callback so it doesn't get garbage collected.
    callbacks.push(new SyscallCallback(frida, callback));

    // Return pointer to the instructions.
    return callbacks[callbacks.length - 1].frida;
}