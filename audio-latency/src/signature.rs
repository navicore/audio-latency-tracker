use crate::config::SignatureAlgorithm;

pub trait AudioSignature {
    fn calculate(&self, data: &[u8], silence_threshold: u16) -> Option<u32>;
}

pub struct RollingHashSignature;
pub struct Crc32Signature;
pub struct XxHashSignature;

impl AudioSignature for RollingHashSignature {
    fn calculate(&self, data: &[u8], silence_threshold: u16) -> Option<u32> {
        let mut hash: u32 = 0;
        let mut has_audio = false;
        let mut i = 0;

        while i + 1 < data.len() {
            let sample = (data[i] as u16) | ((data[i + 1] as u16) << 8);

            // Check if sample is above silence threshold
            if sample.abs_diff(0x8000) > silence_threshold {
                has_audio = true;
                hash = hash.wrapping_mul(31).wrapping_add(sample as u32);
            }
            i += 2;
        }

        if has_audio {
            Some(hash)
        } else {
            None
        }
    }
}

impl AudioSignature for Crc32Signature {
    fn calculate(&self, data: &[u8], silence_threshold: u16) -> Option<u32> {
        const CRC32_POLY: u32 = 0xEDB88320;
        let mut crc: u32 = 0xFFFFFFFF;
        let mut has_audio = false;
        let mut i = 0;

        while i + 1 < data.len() {
            let sample = (data[i] as u16) | ((data[i + 1] as u16) << 8);

            if sample.abs_diff(0x8000) > silence_threshold {
                has_audio = true;

                // Process both bytes of the sample
                for &byte in &[data[i], data[i + 1]] {
                    crc ^= byte as u32;
                    for _ in 0..8 {
                        if crc & 1 != 0 {
                            crc = (crc >> 1) ^ CRC32_POLY;
                        } else {
                            crc >>= 1;
                        }
                    }
                }
            }
            i += 2;
        }

        if has_audio {
            Some(!crc)
        } else {
            None
        }
    }
}

impl AudioSignature for XxHashSignature {
    fn calculate(&self, data: &[u8], silence_threshold: u16) -> Option<u32> {
        // XXH32 constants
        const PRIME32_1: u32 = 2654435761;
        const PRIME32_2: u32 = 2246822519;
        const PRIME32_3: u32 = 3266489917;
        const PRIME32_4: u32 = 668265263;
        const PRIME32_5: u32 = 374761393;

        let mut acc = PRIME32_5;
        let mut has_audio = false;
        let mut i = 0;

        while i + 1 < data.len() {
            let sample = (data[i] as u16) | ((data[i + 1] as u16) << 8);

            if sample.abs_diff(0x8000) > silence_threshold {
                has_audio = true;

                // Process sample as u32
                let val = sample as u32;
                acc = acc.wrapping_add(val.wrapping_mul(PRIME32_3));
                acc = acc.rotate_left(17).wrapping_mul(PRIME32_4);
            }
            i += 2;
        }

        if has_audio {
            // Final mixing
            acc ^= acc >> 15;
            acc = acc.wrapping_mul(PRIME32_2);
            acc ^= acc >> 13;
            acc = acc.wrapping_mul(PRIME32_3);
            acc ^= acc >> 16;

            Some(acc)
        } else {
            None
        }
    }
}

pub fn create_signature(algorithm: SignatureAlgorithm) -> Box<dyn AudioSignature> {
    match algorithm {
        SignatureAlgorithm::RollingHash => Box::new(RollingHashSignature),
        SignatureAlgorithm::Crc32 => Box::new(Crc32Signature),
        SignatureAlgorithm::XxHash => Box::new(XxHashSignature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_silence_detection() {
        let silence = vec![0x00, 0x80; 128]; // 0x8000 = silence in 16-bit PCM
        let threshold = 256;

        let rolling = RollingHashSignature;
        assert_eq!(rolling.calculate(&silence, threshold), None);

        let crc = Crc32Signature;
        assert_eq!(crc.calculate(&silence, threshold), None);

        let xxhash = XxHashSignature;
        assert_eq!(xxhash.calculate(&silence, threshold), None);
    }

    #[test]
    fn test_audio_detection() {
        let mut audio = vec![0x00, 0x80; 64];
        audio.extend(vec![0x00, 0x90; 64]); // Non-silence
        let threshold = 256;

        let rolling = RollingHashSignature;
        assert!(rolling.calculate(&audio, threshold).is_some());

        let crc = Crc32Signature;
        assert!(crc.calculate(&audio, threshold).is_some());

        let xxhash = XxHashSignature;
        assert!(xxhash.calculate(&audio, threshold).is_some());
    }
}
