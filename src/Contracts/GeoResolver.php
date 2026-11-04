<?php

namespace Mainul\PasswordPolicy\Contracts;

interface GeoResolver
{
    /** Two-letter ISO country code for the IP address, or null when unknown. */
    public function country(string $ip): ?string;
}
