fn main(CID: pub str<59>, hash: pub str<64>) {
    let mut (multibase, CIDbytes) = CID.as_bytes().as_slice().pop_front();
    assert(multibase == 66); // Assert that the base is base32

    println(CID);
    println(hash);
    println(CID.as_bytes());
    println(hash.as_bytes());

    // Map ASCII symbols to base32 encodings
    let mut base32: [[u1;5];96] = [[0,0,0,0,0];96];

    base32[65] = [0,0,0,0,0];
    base32[66] = [0,0,0,0,1];
    base32[67] = [0,0,0,1,0];
    base32[68] = [0,0,0,1,1];
    base32[69] = [0,0,1,0,0];
    base32[70] = [0,0,1,0,1];
    base32[71] = [0,0,1,1,0];
    base32[72] = [0,0,1,1,1];
    base32[73] = [0,1,0,0,0];
    base32[74] = [0,1,0,0,1];
    base32[75] = [0,1,0,1,0];
    base32[76] = [0,1,0,1,1];
    base32[77] = [0,1,1,0,0];
    base32[78] = [0,1,1,0,1];
    base32[79] = [0,1,1,1,0];
    base32[80] = [0,1,1,1,1];
    base32[81] = [1,0,0,0,0];
    base32[82] = [1,0,0,0,1];
    base32[83] = [1,0,0,1,0];
    base32[84] = [1,0,0,1,1];
    base32[85] = [1,0,1,0,0];
    base32[86] = [1,0,1,0,1];
    base32[87] = [1,0,1,1,0];
    base32[88] = [1,0,1,1,1];
    base32[89] = [1,1,0,0,0];
    base32[90] = [1,1,0,0,1];
    base32[50] = [1,1,0,1,0];
    base32[51] = [1,1,0,1,1];
    base32[52] = [1,1,1,0,0];
    base32[53] = [1,1,1,0,1];
    base32[54] = [1,1,1,1,0];
    base32[55] = [1,1,1,1,1];

    // Decode CID
    let mut buffer: [u1;290] = [0;290]; 
    for i in 0..58 {
        buffer[i*5]     = base32[CIDbytes[i]][0];
        buffer[i*5+1]   = base32[CIDbytes[i]][1];
        buffer[i*5+2]   = base32[CIDbytes[i]][2];
        buffer[i*5+3]   = base32[CIDbytes[i]][3];
        buffer[i*5+4]   = base32[CIDbytes[i]][4];
    }

    // Needs to be in nibbles for hex encoding
    // Ignore first 4 bytes for version, multicodec, multihash, and length
    let mut result: [u8;64] = [0;64];
    for i in 8..buffer.len() / 4 {
        let nibble: [u1;4] = [buffer[i*4], buffer[i*4+1], buffer[i*4+2], buffer[i*4+3]];
        result[i-8] = binary_to_4bit_integer(nibble);
    }

    let mut digest: [u8;64] = result.map(|r| four_bit_to_hex(r));
    assert(digest == hash.as_bytes()); // Assert that the decoded hash is equal to input hash

}

fn binary_to_4bit_integer(nibble: [u1; 4]) -> u8 {
    let mut result: u8 = 0;
    for i in 0..4 {
        result += (nibble[i] as u8) * ((2).pow_32(3 - i as Field)) as u8;
    }
    result
}

fn four_bit_to_hex(nibble: u8) -> u8 {
    assert(nibble < 16); // Ensure it's a 4-bit integer
    let hex_chars = "0123456789ABCDEF".as_bytes();
    hex_chars[nibble]
}
