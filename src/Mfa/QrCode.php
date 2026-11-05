<?php

namespace Mainul\PasswordPolicy\Mfa;

/**
 * Optional QR rendering. Needs `bacon/bacon-qr-code`; without it the enrol
 * page shows the secret key for manual entry instead.
 */
class QrCode
{
    public static function available(): bool
    {
        return class_exists(\BaconQrCode\Writer::class);
    }

    /** SVG markup for the text, or null when the library is not installed. */
    public static function svg(string $text, int $size = 220): ?string
    {
        if (! self::available()) {
            return null;
        }

        $renderer = new \BaconQrCode\Renderer\ImageRenderer(
            new \BaconQrCode\Renderer\RendererStyle\RendererStyle($size),
            new \BaconQrCode\Renderer\Image\SvgImageBackEnd()
        );

        return (new \BaconQrCode\Writer($renderer))->writeString($text);
    }
}
