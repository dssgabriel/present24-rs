#[inline(always)]
pub fn radix_sort(vec: &mut Vec<u64>, tmp: &mut [u64]) {
    let len = vec.len();

    radix_sort_pass(vec, tmp, &len, 0);
    radix_sort_pass(tmp, vec, &len, 8);
    radix_sort_pass(vec, tmp, &len, 16);

    for i in 0..len {
        vec[i] = tmp[i];
    }
}

#[inline(always)]
fn radix_sort_pass(src: &mut [u64], dst: &mut [u64], len: &usize, shift: usize) {
    let mut index = [0usize; 256];
    let mut next_index = 0;

    for i in 0..*len {
        let j: usize = ((src[i] >> shift) & 0xff) as usize;
        index[j] += 1;
    }

    for i in 0..256 {
        let count = index[i];
        index[i] = next_index;
        next_index += count;
    }

    for i in 0..*len {
        let j: usize = ((src[i] >> shift) & 0xff) as usize;
        dst[index[j]] = src[i];
        index[j] += 1; // Increase by one to get the next position.
    }
}
