/**
 * Additional References:
 * 
 *      - MD4: rfc1320
 * 
 */

#include "Config.hpp"
#include "Krypton.hpp"

#ifndef ROTATE_LEFT
#define ROTATE_LEFT(x,c) (((x) << (c)) | ((x) >> (32 - (c))))
#else
#error "LEFT_ROTATE macro has already been defined."
#endif // LEFT_ROTATE

uint32_t h0, h1, h2, h3;

/**
 * Calculate the MD5 hash of the input string.
 * 
 * References:
 * 
 *      - RFC 1321 - The MD5 Message-Digest Algorithm
 *        https://tools.ietf.org/html/rfc1321
 * 
 */
void md5(uint8_t* initial_msg, size_t initial_len) {
    // Message to prepare
    //uint8_t* msg = nullptr;
    
    // Note: All variables are unsigned 32-bit integers and wrap modulo 2^32
    // when calculating.
    //
    // r specifies the per-round shift amounts
    uint32_t r[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    // Use binary integer part of the sines of integers (in radians) as constants
    // Initialize variables:
    uint32_t k[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;

    // Pre-processing: adding a single 1 bit
    // Append "1" bit to message
    // Note: The input bytes are considered as bit strings, where the
    // first bit is the most significant bit of the byte.[37]

    // Pre-processing: padding with zeros
    // Append "0" bit until message length in bit = 448 (mod 512)
    // Append length mod (2 pow 64) to message
    int new_len = ((((initial_len + 8) / 64) + 1) * 64) - 8;

    // also appends "0"
    // We alloc also 64 extra bytes...
    uint8_t* msg = static_cast<uint8_t *>(calloc(new_len + 64, 1)); 

    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 128; // write the "1" bit

    uint32_t bits_len = 8 * initial_len; // Note: we append the len
    memcpy(msg + new_len, &bits_len, 4); // in bits at the end of the buffer

    // Process the message in successive 512-bit chunks:
    // for each 512-bit chunk of message:
    int offset;

    for (offset = 0; offset < new_len; offset += (512 / 8)) {
        // Break chunk into sixteen 32-bit words w[j], 0 <= j <= 15.
        uint32_t* w = (uint32_t *) (msg + offset);

        // Initialize the hash value for this chunk.
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;

        // Main loop
        uint32_t i;

        for (i = 0; i < 64; i++) {
            uint32_t f, g;

            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }

            uint32_t temp = d;
            d = c;
            c = b;
            //printf("rotateleft(%x + %x + %x + %x, %d)\n", a, f, k[i], w[g], r[i]);
            b = b + ROTATE_LEFT((a + f + k[i] + w[g]), r[i]);
            a = temp;
        }

        // Add this chunk's hash to result so far.
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    // Cleanup
    free(msg);
}

namespace Krypton
{

class MD5
{
// TODO: Change visibility of this section to private or
// protected once the refactor is complete.
public:
    //

// TODO: Change visibility of this section to private or
// protected once the refactor is complete.
public:

    /**
     * In each bit position, F acts as a conditional: if X
     * then Y else Z. The function F could have been defined
     * using addition instead of OR, since XY and (~X)Z will
     * never have 1's in the same bit position.
     * 
     * It is interesting to note that if the bits of X, Y,
     * and Z are independent and unbiased, each bit of
     * F(X,Y,Z) will be independent and unbiased.
     * 
     */
    static constexpr uint32_t F(uint32_t X, uint32_t Y, uint32_t Z)
    {
        return ((X & Y) | ((~X) & Z));
    }

    static constexpr uint32_t G(uint32_t X, uint32_t Y, uint32_t Z)
    {
        return ((X & Z) | (Y & (~Z)));
    }

    static constexpr uint32_t H(uint32_t X, uint32_t Y, uint32_t Z)
    {
        return ((X) ^ (Y) ^ (Z));
    }

    static constexpr uint32_t I(uint32_t X, uint32_t Y, uint32_t Z)
    {
        return ((Y) ^ ((X) | (~Z)));
    }

public:
    //
};

} // namespace Krypton

/**
 * Calculate the MD5 hash of the input string.
 * 
 * References:
 * 
 *      - RFC 1321 - The MD5 Message-Digest Algorithm
 *        https://tools.ietf.org/html/rfc1321
 * 
 *      - RFC 1320 - The MD4 Message-Digest Algorithm
 *        https://tools.ietf.org/html/rfc1320
 * 
 */
void MD5(uint8_t* initial_msg, size_t initial_len) {
    // Note: All variables are unsigned 32-bit integers and wrap modulo 2^32
    // when calculating.
    //
    // r specifies the per-round shift amounts
    uint32_t r[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    /**
     * Step 1 - Append Padding Bits
     * 
     * The message is "padded" (extended) so that its length
     * (in bits) is congruent to 448 mod 512. In other words,
     * the message is extended so that it is just 64 bits
     * shy of being a multiple of 512 bits long. Padding is
     * always performed, even if the length of the messaage
     * is already congruent to 448 mod 512.
     * 
     * Padding is performed as follows: a single "1" bit is
     * appended to the message, and then "0" bits are
     * appended so that the length in bits of the padded
     * message becomes congruent to 448 mod 512. In all, at
     * least one bit and at most 512 bits are appended.
     * 
     */
    size_t length_after_padding = ((((initial_len + 8) / 64) + 1) * 64) - 8;

    /**
     * Step 3 - Initialize Message Digest Buffer
     * 
     * A four-word buffer (h0, h1, h2, h3) is used to compute
     * the message digest. Here each of h0, h1, h2, and h3
     * is a 32-bit register. These registers are initialized
     * to the following values in hexadecimal (low-order
     * bytes first):
     * 
     * word h0: 01 23 45 67
     * word h1: 89 ab cd ef
     * word h2: fe dc ba 98
     * word h3: 76 54 32 10
     * 
     */
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;

    // also appends "0"
    // We alloc also 64 extra bytes...
    uint8_t* msg = static_cast<uint8_t *>(calloc(length_after_padding + 64, 1)); 

    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 128; // write the "1" bit

    uint32_t bits_len = 8 * initial_len; // Note: we append the len
    memcpy(msg + length_after_padding, &bits_len, 4); // in bits at the end of the buffer

    /**
     * Step 4 - Process Message in 16-Word Blocks
     * 
     * This step uses a 64-element table constructed from
     * the sine function. Let T[i] denote the i-th element
     * of the table, which is equal to the integer part of
     * 4294967296 times abs(sin(i)), where i is in radians.
     * 
     */
    uint32_t T[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    for (size_t offset = 0; offset < length_after_padding; offset += 16) {
        // Break off one of the sixteen 32-bit words.
        uint32_t* w = reinterpret_cast<uint32_t *>(msg + offset);

        // Initialize the hash value for this chunk.
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;

        for (uint32_t i = 0; i < 64; i++) {
            uint32_t f = 0;
            uint32_t g = 0;

            if (i < 16) {
                f = Krypton::MD5::F(b, c, d);
                g = i;
            } else if (i < 32) {
                f = Krypton::MD5::G(b, c, d);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = Krypton::MD5::H(b, c, d);
                g = (3 * i + 5) % 16;
            } else {
                f = Krypton::MD5::I(b, c, d);
                g = (7 * i) % 16;
            }

            uint32_t temp = d;
            d = c;
            c = b;
            b = b + ROTATE_LEFT((a + f + T[i] + w[g]), r[i]);
            a = temp;
        }

        // Add this chunk's hash to result so far.
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    // Cleanup
    free(msg);
}

namespace Krypton
{

class Application
{
public:
    static std::string HelpMenu() { return "Usage: krypton <filename> [<filename> ...]"; }
    static std::string Version() { return "Version Information"; }
};

} // namespace Krypton

namespace Options = boost::program_options;

int main(int argc, char *argv[])
{
    std::vector<std::string> filenames;

    Options::options_description generic("Generic Options");
    generic.add_options()
        ("help", "Display this help message")
        ("version", "Display version information and exit")
    ;

    Options::options_description execution("Execution Options");
    execution.add_options()
        ("hash-function,F", Options::value<std::string>()->default_value("MD5"), "Hashing algorithm to use")
    ;

    Options::options_description hidden("Hidden Options");
    hidden.add_options()
        ("input-file", Options::value<std::vector<std::string>>(&filenames), "Input file(s) to hash")
    ;

    Options::options_description cmdline("Command-Line Options");
    cmdline
        .add(generic)
        .add(execution)
        .add(hidden)
    ;

    Options::options_description visible("Program Options");
    visible
        .add(generic)
        .add(execution);

    Options::positional_options_description pos;
    pos.add("input-file", -1);

    Options::variables_map var_map;
    Options::store(
        Options::command_line_parser(argc, argv)
            .options(cmdline)
            .positional(pos)
            .run(),
        var_map
    );
    Options::notify(var_map);

    if (var_map.count("help")) {
        std::cout << visible << std::endl;
        return EXIT_SUCCESS;
    }

    if (var_map.count("version")) {
        std::cout << Krypton::Application::Version() << std::endl;
        return EXIT_SUCCESS;
    }

    for (const auto& filename : filenames) {
        unsigned char* msg = reinterpret_cast<unsigned char *>(const_cast<char *>(filename.c_str()));
        size_t len = strlen(reinterpret_cast<char *>(msg));
        uint8_t* p;

        md5(msg, len);
        p = (uint8_t *) &h0;
        printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
        p = (uint8_t *) &h1;
        printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
        p = (uint8_t *) &h2;
        printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
        p = (uint8_t *) &h3;
        printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
        puts("");

        MD5(msg, len);
        p = (uint8_t *) &h0;
        printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
        p = (uint8_t *) &h1;
        printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
        p = (uint8_t *) &h2;
        printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
        p = (uint8_t *) &h3;
        printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3]);
        puts("");
    }

    return EXIT_SUCCESS;
}

