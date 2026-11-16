#include "../src/bmp.hpp"
#include "../src/stego.hpp"
#include <iostream>
#include <string>

using namespace stego;
static int total = 0, fails = 0;
#define CHECK(x) do { ++total; if (!(x)) { ++fails; std::cerr << "FAIL line " << __LINE__ << ": " #x "\n"; } } while (0)
#define THROWS(x) do { ++total; bool t=false; try { x; } catch(...) { t=true; } if(!t){++fails;std::cerr<<"FAIL(no throw) line "<<__LINE__<<"\n";} } while(0)

static Bitmap solid(int w, int h, uint8_t v) { Bitmap b; b.width=w; b.height=h; b.pixels.assign(size_t(w)*h*3, v); return b; }

int main() {
    // round-trip a text message
    Bitmap img = solid(64, 64, 120);
    std::string secret = "FLAG{st3g0_1s_fun} — meet at 10.0.0.5";
    std::vector<uint8_t> data(secret.begin(), secret.end());
    embed(img, data, "p@ss");
    auto out = extract(img, "p@ss");
    CHECK(std::string(out.begin(), out.end()) == secret);

    // wrong password fails cleanly (does not return the secret)
    THROWS(extract(img, "wrong"));

    // capacity enforced
    Bitmap tiny = solid(8, 8, 0);
    THROWS(embed(tiny, std::vector<uint8_t>(500, 'A'), "k"));

    // binary payload with all byte values
    std::vector<uint8_t> bin(256);
    for (int i = 0; i < 256; ++i) bin[i] = uint8_t(i);
    Bitmap img2 = solid(100, 100, 50);
    embed(img2, bin, "key");
    CHECK(extract(img2, "key") == bin);

    // BMP save/load round-trip preserves pixels
    img2.save("/tmp/_stego_test.bmp");
    Bitmap loaded = Bitmap::load("/tmp/_stego_test.bmp");
    CHECK(loaded.width == 100 && loaded.height == 100);
    CHECK(loaded.pixels == img2.pixels);
    CHECK(extract(loaded, "key") == bin);

    // detection: a clean image with a natural (lumpy) histogram has unequal value pairs,
    // so it scores LOW; embedding over most of it balances the pairs and scores HIGH.
    const uint8_t palette[8] = {30, 33, 70, 77, 128, 133, 200, 207};  // f(2k) != f(2k+1)
    Bitmap clean; clean.width=200; clean.height=200; clean.pixels.resize(size_t(200)*200*3);
    for (size_t i=0;i<clean.pixels.size();++i) clean.pixels[i]=palette[(i*2654435761u>>13)&7];
    Bitmap filled = clean;
    embed(filled, std::vector<uint8_t>(filled.channelCount()/8 - 16, 0x5A), "x");
    double pc = chiSquareProbability(clean), pf = chiSquareProbability(filled);
    CHECK(pc < 0.5);
    CHECK(pf > 0.9);

    std::cout << (total - fails) << "/" << total << " checks passed\n";
    return fails ? 1 : 0;
}
