const TARGET_DLL = "QQMusicCommon.dll";

function findAndLog(dllName, funcName) {
  const module = Process.getModuleByName(dllName);
  if (!module) {
    throw new Error(`Could not find module '${dllName}'. QQ Music might not have loaded it yet or the name is incorrect.`);
  }

  const address = module.findExportByName(funcName);

  console.log(`Searching for ${funcName} in ${dllName}... Address: ${address}`);
  if (address === null) {
      throw new Error(`Could not find export '${funcName}' in ${dllName}. QQ Music version might be incompatible.`);
  }
  return address;
}

function initialize() {
    try {
        var EncAndDesMediaFileConstructorAddr = findAndLog(TARGET_DLL, "??0EncAndDesMediaFile@@QAE@XZ");
        var EncAndDesMediaFileDestructorAddr = findAndLog(TARGET_DLL, "??1EncAndDesMediaFile@@QAE@XZ");
        var EncAndDesMediaFileOpenAddr = findAndLog(TARGET_DLL, "?Open@EncAndDesMediaFile@@QAE_NPB_W_N1@Z");
        var EncAndDesMediaFileGetSizeAddr = findAndLog(TARGET_DLL, "?GetSize@EncAndDesMediaFile@@QAEKXZ");
        var EncAndDesMediaFileReadAddr = findAndLog(TARGET_DLL, "?Read@EncAndDesMediaFile@@QAEKPAEK_J@Z");
        var EncAndDesMediaFileConstructor = new NativeFunction(EncAndDesMediaFileConstructorAddr, "pointer", ["pointer"], "thiscall");
        var EncAndDesMediaFileDestructor = new NativeFunction(EncAndDesMediaFileDestructorAddr, "void", ["pointer"], "thiscall");
        var EncAndDesMediaFileOpen = new NativeFunction(EncAndDesMediaFileOpenAddr, "bool", ["pointer", "pointer", "bool", "bool"], "thiscall");
        var EncAndDesMediaFileGetSize = new NativeFunction(EncAndDesMediaFileGetSizeAddr, "uint32", ["pointer"], "thiscall");
        var EncAndDesMediaFileRead = new NativeFunction(EncAndDesMediaFileReadAddr, "uint", ["pointer", "pointer", "uint32", "uint64"], "thiscall");

        rpc.exports = {
          decrypt: function (srcFileName, tmpFileName) {
            var EncAndDesMediaFileObject = Memory.alloc(0x28);
            EncAndDesMediaFileConstructor(EncAndDesMediaFileObject);

            var fileNameUtf16 = Memory.allocUtf16String(srcFileName);
            var success = EncAndDesMediaFileOpen(EncAndDesMediaFileObject, fileNameUtf16, 1, 0);

            if (!success) {
                console.error(`Failed to open file: ${srcFileName}`);
                EncAndDesMediaFileDestructor(EncAndDesMediaFileObject);
                return;
            }

            var fileSize = EncAndDesMediaFileGetSize(EncAndDesMediaFileObject);
            console.log(`File size: ${fileSize}`);

            if (fileSize === 0) {
                console.warn(`File size is 0 for: ${srcFileName}`);
                EncAndDesMediaFileDestructor(EncAndDesMediaFileObject);
                return;
            }

            var buffer = Memory.alloc(fileSize);
            EncAndDesMediaFileRead(EncAndDesMediaFileObject, buffer, fileSize, 0);

            var data = buffer.readByteArray(fileSize);
            EncAndDesMediaFileDestructor(EncAndDesMediaFileObject);

            var tmpFile = new File(tmpFileName, "wb");
            tmpFile.write(data);
            tmpFile.close();
            console.log(`Decryption complete. Saved to: ${tmpFileName}`);
          },
        };
    } catch (e) {
        console.error("An error occurred during agent initialization:");
        console.error(e.stack);
    }
}

setImmediate(initialize);