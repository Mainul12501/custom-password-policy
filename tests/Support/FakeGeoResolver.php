<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Mainul\PasswordPolicy\Contracts\GeoResolver;

/** 198.x => BD, 203.x => SG, everything else unknown. */
class FakeGeoResolver implements GeoResolver
{
    public function country(string $ip): ?string
    {
        return match (true) {
            str_starts_with($ip, '198.') => 'BD',
            str_starts_with($ip, '203.') => 'SG',
            default                      => null,
        };
    }
}
