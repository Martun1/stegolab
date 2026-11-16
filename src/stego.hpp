// stego.hpp: LSB steganography (embed/extract) + chi-square steganalysis.
// Payload is whitened with a SHA-256 keystream derived from the password, so a
// wrong password yields garbage, and the magic/length check fails cleanly.
// Author: Martin Ivanov (Martun1) | License: MIT
#pragma once

#include "bmp.hpp"
#include "sha256.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace stego {

constexpr std::array<uint8_t, 4> MAGIC = {'S', 'T', 'G', '1'};

// SHA-256 based keystream in CTR mode: SHA256(password | counter) blocks.
class Keystream {
    std::string pw_;
    uint64_t counter_ = 0;
    std::string block_;
    size_t pos_ = 0;

  public:
    explicit Keystream(const std::string& password) : pw_(password) { refill(); }
    uint8_t next() {
        if (pos_ >= block_.size()) refill();
        return static_cast<uint8_t>(block_[pos_++]);
    }

  private:
    void refill() {
        hg::SHA256 h;
        h.update(pw_);
        uint8_t ctr[8];
        for (int i = 0; i < 8; ++i) ctr[i] = static_cast<uint8_t>(counter_ >> (8 * i));
        h.update(std::string(reinterpret_cast<char*>(ctr), 8));
        std::string hex = h.hexdigest();
        block_.clear();
        for (size_t i = 0; i < hex.size(); i += 2)
            block_.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
        pos_ = 0;
        ++counter_;
    }
};

inline size_t capacityBytes(const Bitmap& b) { return b.channelCount() / 8; }

/// Embed `data` into a copy of `img` using 1 LSB per channel byte. Throws if it won't fit.
inline void embed(Bitmap& img, const std::vector<uint8_t>& data, const std::string& password) {
    std::vector<uint8_t> frame;
    uint32_t len = static_cast<uint32_t>(data.size());
    frame.insert(frame.end(), MAGIC.begin(), MAGIC.end());
    for (int i = 0; i < 4; ++i) frame.push_back(static_cast<uint8_t>(len >> (8 * i)));
    frame.insert(frame.end(), data.begin(), data.end());

    Keystream ks(password);
    for (auto& byte : frame) byte ^= ks.next();  // whiten header + payload

    const size_t bitsNeeded = frame.size() * 8;
    if (bitsNeeded > img.channelCount())
        throw std::runtime_error("message too large: needs " + std::to_string(frame.size()) +
                                 " bytes, capacity is " + std::to_string(capacityBytes(img)) + " bytes");
    size_t bit = 0;
    for (uint8_t byte : frame)
        for (int i = 0; i < 8; ++i, ++bit) {
            uint8_t b = (byte >> i) & 1;
            img.pixels[bit] = (img.pixels[bit] & 0xFE) | b;
        }
}

/// Extract a message previously embedded with the same password. Throws on magic/length mismatch.
inline std::vector<uint8_t> extract(const Bitmap& img, const std::string& password) {
    auto readBytes = [&](size_t offsetBits, size_t count) {
        std::vector<uint8_t> out(count, 0);
        for (size_t n = 0; n < count; ++n)
            for (int i = 0; i < 8; ++i) {
                size_t bit = offsetBits + n * 8 + i;
                if (bit >= img.channelCount()) throw std::runtime_error("image too small / corrupt");
                out[n] |= (img.pixels[bit] & 1) << i;
            }
        return out;
    };
    Keystream ks(password);
    auto head = readBytes(0, 8);
    for (auto& b : head) b ^= ks.next();
    for (int i = 0; i < 4; ++i)
        if (head[i] != MAGIC[i])
            throw std::runtime_error("no hidden message found (wrong password or clean image)");
    uint32_t len = head[4] | (head[5] << 8) | (head[6] << 16) | (head[7] << 24);
    if (static_cast<size_t>(len) > capacityBytes(img))
        throw std::runtime_error("declared length is impossible (wrong password or corrupt data)");
    auto body = readBytes(64, len);
    for (auto& b : body) b ^= ks.next();  // keystream continues past the 8 header bytes
    return body;
}

/// Chi-square p-value over one prefix of `n` channels: high = pairs (2k,2k+1) suspiciously balanced.
inline double chiSquarePrefix(const Bitmap& img, size_t n) {
    std::array<uint64_t, 256> hist{};
    for (size_t i = 0; i < n; ++i) ++hist[img.pixels[i]];

    double chi = 0.0;
    int df = 0;
    for (int k = 0; k < 128; ++k) {
        uint64_t even = hist[2 * k], odd = hist[2 * k + 1];
        double expected = (even + odd) / 2.0;
        if (expected < 5) continue;  // skip low-count bins for a stable test
        chi += (even - expected) * (even - expected) / expected;
        ++df;
    }
    if (df == 0) return 0.0;
    // Upper incomplete gamma via a simple series/continued-fraction (regularized Q).
    double k = df / 2.0, x = chi / 2.0;
    double q;
    if (x < k + 1) {  // series for the lower regularized gamma P, Q = 1 - P
        double term = 1.0 / k, sum = term;
        for (int i = 1; i < 200; ++i) { term *= x / (k + i); sum += term; }
        double lnP = -x + k * std::log(x + 1e-12) - std::lgamma(k) + std::log(sum + 1e-300);
        q = 1.0 - std::exp(lnP);
    } else {  // continued fraction for Q directly
        double b = x + 1 - k, c = 1e300, d = 1.0 / b, h = d;
        for (int i = 1; i < 200; ++i) {
            double an = -1.0 * i * (i - k);
            b += 2;
            d = an * d + b; if (std::fabs(d) < 1e-300) d = 1e-300;
            c = b + an / c; if (std::fabs(c) < 1e-300) c = 1e-300;
            d = 1 / d; double del = d * c; h *= del;
            if (std::fabs(del - 1) < 1e-10) break;
        }
        double lnQ = -x + k * std::log(x + 1e-12) - std::lgamma(k) + std::log(h + 1e-300);
        q = std::exp(lnQ);
    }
    // p(embedded) is high when chi is SMALL (pairs too balanced) -> p-value Q itself.
    double p = q;
    return p < 0 ? 0 : p > 1 ? 1 : p;
}

/// Steganalysis over the whole image. Sequential LSB embedding fills from the start, so we test
/// growing prefixes and report the most suspicious one (the classic Westfeld-Pfitzmann scan).
/// Returns {probability, embeddedFraction}: fraction estimates how much of the image carries data.
inline std::pair<double, double> chiSquareScan(const Bitmap& img, int steps = 64) {
    const size_t total = img.channelCount();
    double best = 0.0;
    size_t bestN = 0;
    for (int s = 1; s <= steps; ++s) {
        size_t n = total * s / steps;
        if (n < 512) continue;
        double p = chiSquarePrefix(img, n);
        if (p >= best) { best = p; bestN = n; }
        if (p < 0.5 && best > 0.9) break;  // p dropped after a strong hit: end of embedded region
    }
    return {best, total ? double(bestN) / total : 0.0};
}

inline double chiSquareProbability(const Bitmap& img) { return chiSquareScan(img).first; }

/// Render a visual of the LSB plane (each channel's LSB scaled to 0/255) for the bit-plane image.
inline Bitmap lsbPlane(const Bitmap& img) {
    Bitmap out = img;
    for (auto& p : out.pixels) p = (p & 1) ? 255 : 0;
    return out;
}

}  // namespace stego
