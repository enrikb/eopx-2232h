/*

typedef struct _ft_device_list_info_node {
    ULONG Flags;           //   4
    ULONG Type;            //   4
    ULONG ID;              //   4
    DWORD LocId;           //   4
    char SerialNumber[16]; //  16
    char Description[64];  //  64
    FT_HANDLE ftHandle;    //   4
                           // 100 bytes
} FT_DEVICE_LIST_INFO_NODE;

*/
let FT_EE_Read = Module.findExportByName("FTD2XX.dll", "FT_EE_Read");
if (FT_EE_Read != null) {
    Interceptor.attach(FT_EE_Read, {

        onEnter: function (args) {
            //console.log("FT_EE_Read")
            this.the_buff = args[1];
            this.the_buff.add(8).writeU8(5);
        },

        onLeave: function (retval) {
            this.the_buff.add(8).writeU8(5);
            this.the_buff.add(0x3a).writeU8(1);
            this.the_buff.add(0x3d).writeU8(1);
            this.the_buff.add(0x43).writeU8(1);
            var data = Memory.readByteArray(this.the_buff, 128);
            var str1 = Memory.readPointer(this.the_buff.add(16));
            str1 = Memory.readCString(str1);
            var str2 = Memory.readPointer(this.the_buff.add(20));
            str2 = Memory.readCString(str2);
            var str3 = Memory.readPointer(this.the_buff.add(24));
            str3 = Memory.readCString(str3);
            var str4 = Memory.readPointer(this.the_buff.add(28));
            str4 = Memory.readCString(str4);
            //console.log(data);
            console.log(str1, str3, str4);
        }
    });
}

let FT_EE_Program = Module.findExportByName("FTD2XX.dll", "FT_EE_Program");
if (FT_EE_Program != null) {
    Interceptor.attach(FT_EE_Program, {

        onEnter: function (args) {
            console.log("FT_EE_Program")
            this.the_buff = args[1];
            var data = Memory.readByteArray(this.the_buff, 128);
            console.log(data);
        },

        onLeave: function (retval) {
        }
    });
}

let FT_GetDeviceInfoList = Module.findExportByName("FTD2XX.dll", "FT_GetDeviceInfoList");
if (FT_GetDeviceInfoList != null) {
    Interceptor.attach(FT_GetDeviceInfoList, {

        onEnter: function (args) {
            this.the_buff = args[0];
            this.the_size = args[1];
        },

        onLeave: function (retval) {
            var size = this.the_size.readPointer().toInt32() * 100;
            var data = Memory.readByteArray(this.the_buff, size);
            var b = new Uint8Array(data);

            var i;
            for (i = 0; i < size; i += 100) {
                // change 0403:6010 id 6 (2232H) to id 4 (2232C/D)
                if (b[i + 8] == 0x10 && b[i + 9] == 0x60 && b[i + 10] == 3 && b[i + 11] == 4 &&
                    b[i + 4] == 6 && b[i + 5] == 0 && b[i + 6] == 0 && b[i + 7] == 0) {
                    this.the_buff.add(i + 4).writeU8(4);
                }
            }
        }
    });
}

let FT_Write = Module.findExportByName("FTD2XX.dll", "FT_Write");
if (FT_Write != null) {
    Interceptor.attach(FT_Write, {

        onEnter: function (args) {
            var size = args[2].toInt32();
            var data = Memory.readByteArray(args[1], size);

            var bytes = new Uint8Array(data);
            var len;

            var i;
            for (i = 0; i < size; i++) {
                switch (bytes[i]) {
                    case 0x80:
                        i += 2;
                        // make sure GPIOL1 stays as input
                        Memory.writeU8(args[1].add(i), (bytes[i] & 0xdf));
                        break;
                    case 0x24:
                    case 0x82:
                    case 0x86:
                        i += 2;
                        break;
                    case 0x85:
                    case 0x88:
                    case 0x89:
                    case 0xaa:
                    case 0xab:
                        break;
                    case 0x11:
                        // serial (SPI) write: have to skip data, too
                        len = bytes[i + 1] + 256 * bytes[i + 2] + 1;
                        i += 2 + len;
                        break;
                    default:
                        console.log("Unknown command ", bytes[i], " at ", i);
                        console.log(hexdump(data, { offset: i, length: size - i, header: false, ansi: false })); break;
                }
            }
        },

        onLeave: function (retval) {
        }
    });
}