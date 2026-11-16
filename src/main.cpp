// StegoLab: hide and find secret messages in images (LSB steganography),
// then detect them with chi-square steganalysis. C++17, no dependencies.
// Author: Martin Ivanov (Martun1) | License: MIT
#include "bmp.hpp"
#include "stego.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

using namespace stego;

namespace c {
bool on = true;
std::string k(const char* s) { return on ? s : ""; }
std::string R() { return k("\033[0m"); }
std::string B() { return k("\033[1m"); }
std::string D() { return k("\033[2m"); }
std::string G() { return k("\033[92m"); }
std::string Rd() { return k("\033[91m"); }
std::string Y() { return k("\033[93m"); }
std::string CY() { return k("\033[96m"); }
std::string M() { return k("\033[95m"); }
}  // namespace c

static const char* VERSION = "1.0.0";

static std::vector<uint8_t> readFile(const std::string& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read " + p);
    return {std::istreambuf_iterator<char>(in), {}};
}

static void banner() {
    std::cout << c::M() << c::B() << R"(
   ___ _            __    _
  / __| |_ ___ __ _/ _|  | |   __ _ _
  \__ \  _/ -_) _` |  _| | |__/ _` | '_ \
  |___/\__\___\__, |_|   |____\__,_|_.__/
              |___/)" << c::R() << c::D() << "  v" << VERSION << " — LSB steganography & detection\n\n" << c::R();
}

static void bar(double p) {
    int n = static_cast<int>(p * 30 + 0.5);
    std::string col = p > 0.75 ? c::Rd() : p > 0.4 ? c::Y() : c::G();
    std::cout << col << std::string(n, '#') << c::R() << c::D() << std::string(30 - n, '-') << c::R();
}

static int cmd_embed(const std::string& cover, const std::string& msgArg, const std::string& out,
                     const std::string& pw, bool msgIsFile) {
    Bitmap img = Bitmap::load(cover);
    std::vector<uint8_t> data = msgIsFile ? readFile(msgArg) : std::vector<uint8_t>(msgArg.begin(), msgArg.end());
    embed(img, data, pw);
    img.save(out);
    double used = 100.0 * (data.size() + 8) / capacityBytes(img);
    std::cout << "  " << c::G() << "[+]" << c::R() << " hid " << c::B() << data.size() << c::R() << " bytes in "
              << img.width << "x" << img.height << " image\n";
    std::cout << "  " << c::G() << "[+]" << c::R() << " wrote " << out << c::D() << "  (" << used
              << "% of capacity used)" << c::R() << "\n";
    std::cout << "  " << c::D() << "extract with: stegolab extract \"" << out << "\" -p <password>" << c::R() << "\n";
    return 0;
}

static int cmd_extract(const std::string& stego, const std::string& pw, const std::string& out) {
    Bitmap img = Bitmap::load(stego);
    auto data = extract(img, pw);
    if (!out.empty()) {
        std::ofstream(out, std::ios::binary).write(reinterpret_cast<char*>(data.data()), data.size());
        std::cout << "  " << c::G() << "[+]" << c::R() << " recovered " << data.size() << " bytes → " << out << "\n";
    } else {
        std::cout << "  " << c::G() << "[+]" << c::R() << " hidden message (" << data.size() << " bytes):\n\n";
        std::cout << c::CY();
        std::cout.write(reinterpret_cast<char*>(data.data()), data.size());
        std::cout << c::R() << "\n";
    }
    return 0;
}

static int cmd_detect(const std::vector<std::string>& files) {
    std::cout << "  " << c::B() << "chi-square steganalysis" << c::R() << c::D()
              << "  (high = LSB plane looks modified)" << c::R() << "\n\n";
    int flagged = 0;
    for (const auto& f : files) {
        try {
            Bitmap img = Bitmap::load(f);
            auto [p, frac] = chiSquareScan(img);
            std::cout << "  ";
            bar(p);
            std::string verdict = p > 0.75 ? c::Rd() + "LIKELY HIDDEN DATA" : p > 0.4 ? c::Y() + "suspicious" : c::G() + "clean";
            std::cout << " " << c::B() << int(p * 100) << "%" << c::R() << "  " << verdict << c::R();
            if (p > 0.75) std::cout << c::D() << " (~" << int(frac * 100) << "% of image)" << c::R();
            std::cout << "  " << c::D() << f << c::R() << "\n";
            if (p > 0.75) ++flagged;
        } catch (const std::exception& e) {
            std::cout << "  " << c::Rd() << "error" << c::R() << " " << f << ": " << e.what() << "\n";
        }
    }
    std::cout << "\n  " << c::B() << flagged << c::R() << " of " << files.size() << " image(s) flagged\n";
    return flagged ? 1 : 0;
}

static int cmd_info(const std::string& f) {
    Bitmap img = Bitmap::load(f);
    std::cout << "  " << c::D() << "file     " << c::R() << f << "\n";
    std::cout << "  " << c::D() << "size     " << c::R() << img.width << " x " << img.height << " px (24-bit)\n";
    std::cout << "  " << c::D() << "capacity " << c::R() << c::B() << capacityBytes(img) << c::R()
              << " bytes (" << capacityBytes(img) / 1024 << " KiB) of hidden data\n";
    std::cout << "  " << c::D() << "chi-sq   " << c::R() << int(chiSquareProbability(img) * 100) << "% probability of embedding\n";
    return 0;
}

static int cmd_reveal(const std::string& in, const std::string& out) {
    Bitmap img = Bitmap::load(in);
    lsbPlane(img).save(out);
    std::cout << "  " << c::G() << "[+]" << c::R() << " LSB bit-plane written → " << out
              << c::D() << "  (open it: hidden data shows up as structured noise)" << c::R() << "\n";
    return 0;
}

static void usage() {
    std::cout << "StegoLab: hide & detect secret messages in BMP images\n\n"
                 "Usage:\n"
                 "  stegolab embed   <cover.bmp> -m \"text\"      -o out.bmp -p <password>\n"
                 "  stegolab embed   <cover.bmp> -f secret.txt  -o out.bmp -p <password>\n"
                 "  stegolab extract <stego.bmp> -p <password> [-o recovered.bin]\n"
                 "  stegolab detect  <img1.bmp> [img2.bmp ...]     chi-square steganalysis\n"
                 "  stegolab reveal  <img.bmp>  -o plane.bmp        visualise the LSB bit-plane\n"
                 "  stegolab info    <img.bmp>                      capacity & stats\n\n"
                 "Options:  --no-color\n";
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) SetConsoleMode(h, mode | 0x0004);
#endif
    std::vector<std::string> a;
    std::string msg, file, out, pw = "", cmd;
    bool msgIsFile = false, showBanner = true;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--no-color") c::on = false;
        else if (s == "-m" && i + 1 < argc) { msg = argv[++i]; msgIsFile = false; }
        else if (s == "-f" && i + 1 < argc) { file = argv[++i]; msgIsFile = true; }
        else if (s == "-o" && i + 1 < argc) out = argv[++i];
        else if (s == "-p" && i + 1 < argc) pw = argv[++i];
        else if (s == "--quiet") showBanner = false;
        else a.push_back(s);
    }
    if (a.empty() || a[0] == "-h" || a[0] == "--help") { usage(); return a.empty() ? 1 : 0; }
    if (showBanner) banner();
    try {
        cmd = a[0];
        if (cmd == "embed" && a.size() >= 2) {
            if (out.empty()) throw std::runtime_error("embed needs -o <output.bmp>");
            if (msg.empty() && file.empty()) throw std::runtime_error("embed needs -m \"text\" or -f <file>");
            return cmd_embed(a[1], msgIsFile ? file : msg, out, pw, msgIsFile);
        }
        if (cmd == "extract" && a.size() >= 2) return cmd_extract(a[1], pw, out);
        if (cmd == "detect" && a.size() >= 2) return cmd_detect({a.begin() + 1, a.end()});
        if (cmd == "reveal" && a.size() >= 2) {
            if (out.empty()) throw std::runtime_error("reveal needs -o <plane.bmp>");
            return cmd_reveal(a[1], out);
        }
        if (cmd == "info" && a.size() >= 2) return cmd_info(a[1]);
        usage();
        return 1;
    } catch (const std::exception& e) {
        std::cerr << c::Rd() << "error: " << c::R() << e.what() << "\n";
        return 2;
    }
}
