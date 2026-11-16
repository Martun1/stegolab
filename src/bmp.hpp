// bmp.hpp: minimal 24-bit uncompressed BMP reader/writer (header-only, no dependencies).
// Author: Martin Ivanov (Martun1) | License: MIT
#pragma once

#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace stego {

#pragma pack(push, 1)
struct BmpFileHeader { uint16_t type; uint32_t size; uint16_t r1, r2; uint32_t offset; };
struct BmpInfoHeader {
    uint32_t size; int32_t width, height; uint16_t planes, bpp;
    uint32_t compression, imageSize; int32_t xppm, yppm; uint32_t colors, important;
};
#pragma pack(pop)

class Bitmap {
  public:
    int width = 0, height = 0;
    std::vector<uint8_t> pixels;  // row-major, bottom-up as stored; 3 bytes/pixel (B,G,R)

    static Bitmap load(const std::string& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) throw std::runtime_error("cannot open " + path);
        BmpFileHeader fh{};
        BmpInfoHeader ih{};
        in.read(reinterpret_cast<char*>(&fh), sizeof fh);
        in.read(reinterpret_cast<char*>(&ih), sizeof ih);
        if (fh.type != 0x4D42) throw std::runtime_error(path + ": not a BMP file");
        if (ih.bpp != 24 || ih.compression != 0)
            throw std::runtime_error(path + ": only 24-bit uncompressed BMP is supported (got " +
                                     std::to_string(ih.bpp) + "-bit, compression " + std::to_string(ih.compression) + ")");
        Bitmap b;
        b.width = ih.width;
        b.height = ih.height < 0 ? -ih.height : ih.height;
        b.pixels.resize(static_cast<size_t>(b.width) * b.height * 3);
        const int rowBytes = b.width * 3;
        const int pad = (4 - rowBytes % 4) % 4;
        in.seekg(fh.offset, std::ios::beg);
        for (int y = 0; y < b.height; ++y) {
            in.read(reinterpret_cast<char*>(&b.pixels[static_cast<size_t>(y) * rowBytes]), rowBytes);
            in.seekg(pad, std::ios::cur);
        }
        if (!in) throw std::runtime_error(path + ": unexpected end of file");
        return b;
    }

    void save(const std::string& path) const {
        const int rowBytes = width * 3;
        const int pad = (4 - rowBytes % 4) % 4;
        const uint32_t imageSize = static_cast<uint32_t>((rowBytes + pad) * height);
        BmpFileHeader fh{0x4D42, uint32_t(54 + imageSize), 0, 0, 54};
        BmpInfoHeader ih{40, width, height, 1, 24, 0, imageSize, 2835, 2835, 0, 0};
        std::ofstream out(path, std::ios::binary);
        if (!out) throw std::runtime_error("cannot write " + path);
        out.write(reinterpret_cast<const char*>(&fh), sizeof fh);
        out.write(reinterpret_cast<const char*>(&ih), sizeof ih);
        const char zeros[3] = {0, 0, 0};
        for (int y = 0; y < height; ++y) {
            out.write(reinterpret_cast<const char*>(&pixels[static_cast<size_t>(y) * rowBytes]), rowBytes);
            out.write(zeros, pad);
        }
    }

    size_t channelCount() const { return pixels.size(); }  // usable LSB carriers
};

}  // namespace stego
