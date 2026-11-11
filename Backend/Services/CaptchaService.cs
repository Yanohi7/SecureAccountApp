using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Backend.Services;

public class CaptchaService
{
    private const int Width = 180;
    private const int Height = 56;
    private static readonly (char Character, ulong Rows)[] Glyphs =
    [
        ('A', 0x3A31FC631), ('B', 0x7A31F463E), ('C', 0x3E108420F),
        ('D', 0x7A318C63E), ('E', 0x7E10F421F), ('F', 0x7E10F4210),
        ('H', 0x4631FC631), ('J', 0x1C4214A4C), ('K', 0x4654C5251),
        ('L', 0x42108421F), ('M', 0x4775AC631), ('N', 0x47359C631),
        ('P', 0x7A31F4210), ('R', 0x7A31F5251), ('S', 0x3E107043E),
        ('T', 0x7C8421084), ('U', 0x46318C62E), ('V', 0x46318C544),
        ('X', 0x462A22A31), ('Y', 0x462A21084), ('Z', 0x7C222221F),
        ('3', 0x78217043E), ('4', 0x08CA97C42), ('6', 0x3A10F462E),
        ('7', 0x7C2222108), ('9', 0x3A317842E)
    ];

    private readonly ConcurrentDictionary<string, (string Code, DateTime ExpiresAt)> _challenges = new();

    public (string CaptchaId, string Image) GenerateCaptcha()
    {
        var now = DateTime.UtcNow;
        foreach (var challenge in _challenges)
        {
            if (challenge.Value.ExpiresAt <= now)
                _challenges.TryRemove(challenge.Key, out _);
        }

        var glyphs = new (char Character, ulong Rows)[5];
        for (var i = 0; i < glyphs.Length; i++)
            glyphs[i] = Glyphs[RandomNumberGenerator.GetInt32(Glyphs.Length)];

        var id = Guid.NewGuid().ToString("N");
        _challenges[id] = (new string(glyphs.Select(glyph => glyph.Character).ToArray()), now.AddMinutes(3));
        return (id, "data:image/bmp;base64," + Convert.ToBase64String(RenderImage(glyphs)));
    }

    public bool Validate(string captchaId, string inputCode) =>
        _challenges.TryRemove(captchaId, out var challenge) &&
        challenge.ExpiresAt > DateTime.UtcNow &&
        string.Equals(challenge.Code, inputCode.Trim(), StringComparison.OrdinalIgnoreCase);

    private static byte[] RenderImage((char Character, ulong Rows)[] glyphs)
    {
        const int headerSize = 54;
        const int pixelBytes = Width * Height * 3;
        using var image = new MemoryStream(headerSize + pixelBytes);
        using var writer = new BinaryWriter(image);
        writer.Write((ushort)0x4d42);
        writer.Write(headerSize + pixelBytes);
        writer.Write(0);
        writer.Write(headerSize);
        writer.Write(40);
        writer.Write(Width);
        writer.Write(-Height);
        writer.Write((ushort)1);
        writer.Write((ushort)24);
        writer.Write(0);
        writer.Write(pixelBytes);
        for (var i = 0; i < 4; i++)
            writer.Write(0);

        var pixels = new byte[pixelBytes];
        Array.Fill(pixels, (byte)34);
        var noise = Random.Shared;
        for (var i = 0; i < 420; i++)
            SetPixel(pixels, noise.Next(Width), noise.Next(Height), (byte)noise.Next(58, 144));

        for (var i = 0; i < glyphs.Length; i++)
        {
            var startX = 10 + i * 33 + noise.Next(0, 6);
            var startY = noise.Next(11, 19);
            var tilt = noise.Next(-1, 2);
            for (var row = 0; row < 7; row++)
            {
                for (var column = 0; column < 5; column++)
                {
                    if ((glyphs[i].Rows & (1UL << ((6 - row) * 5 + 4 - column))) == 0)
                        continue;
                    for (var dy = 0; dy < 4; dy++)
                    {
                        for (var dx = 0; dx < 4; dx++)
                            SetPixel(pixels, startX + column * 4 + dx + (row / 2) * tilt,
                                startY + row * 4 + dy, (byte)noise.Next(205, 256));
                    }
                }
            }
        }

        for (var x = 0; x < Width; x++)
            SetPixel(pixels, x, 25 + (int)(8 * Math.Sin(x / 14.0)), 141);

        writer.Write(pixels);
        return image.ToArray();
    }

    private static void SetPixel(byte[] pixels, int x, int y, byte value)
    {
        var offset = (y * Width + x) * 3;
        pixels[offset] = value;
        pixels[offset + 1] = value;
        pixels[offset + 2] = value;
    }
}
