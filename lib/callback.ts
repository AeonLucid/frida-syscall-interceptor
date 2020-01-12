export class SyscallCallback {

    frida: NativePointer;
    native: NativePointer;

    constructor (frida: NativePointer, native: NativePointer) {
        this.frida = frida;
        this.native = native;
    }

}